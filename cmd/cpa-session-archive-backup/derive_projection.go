package main

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const digestRecordSQL = `SELECT request_id,session_id,COALESCE(key_id,''),COALESCE(principal_id,''),
	COALESCE(credential_hash,''),COALESCE(requested_model,''),COALESCE(model,''),COALESCE(outcome,''),
	COALESCE(status_code,0),started_at,completed_at,COALESCE(metadata_json,''),COALESCE(facets_json,''),
	COALESCE(original_ref,''),COALESCE(response_ref,''),original_request_gz,response_gz
	FROM records WHERE request_id=? AND session_id=?`

const maxDigestPayloadBytes = 16 << 20

type digestBlob struct {
	key  string
	data []byte
}

type digestProjection struct {
	cache      map[string]*list.Element
	order      *list.List
	cacheBytes int
	blobReads  int64
}

func newDigestProjection() *digestProjection {
	return &digestProjection{cache: map[string]*list.Element{}, order: list.New()}
}

func boundedGunzip(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	result, err := io.ReadAll(io.LimitReader(reader, maxDigestPayloadBytes+1))
	if err == nil && len(result) > maxDigestPayloadBytes {
		err = errors.New("payload limit")
	}
	return result, err
}

func (projection *digestProjection) blob(ctx context.Context, tx *sql.Tx, key string) ([]byte, error) {
	if cached := projection.cache[key]; cached != nil {
		projection.order.MoveToFront(cached)
		return cached.Value.(digestBlob).data, nil
	}
	var codec string
	var size int64
	if err := tx.QueryRowContext(ctx, "SELECT codec,length(data) FROM blobs WHERE hash=?", key).Scan(&codec, &size); err != nil {
		return nil, err
	}
	if size < 0 || size > maxDigestPayloadBytes {
		return nil, errors.New("blob limit")
	}
	var data []byte
	if err := tx.QueryRowContext(ctx, "SELECT data FROM blobs WHERE hash=?", key).Scan(&data); err != nil {
		return nil, err
	}
	projection.blobReads++
	if codec == "gzip" {
		var err error
		data, err = boundedGunzip(data)
		if err != nil {
			return nil, err
		}
	}
	for (projection.cacheBytes+len(data) > maxDigestPayloadBytes || projection.order.Len() >= 1024) && projection.order.Len() > 0 {
		oldest := projection.order.Back()
		entry := oldest.Value.(digestBlob)
		delete(projection.cache, entry.key)
		projection.cacheBytes -= len(entry.data)
		projection.order.Remove(oldest)
	}
	projection.cache[key] = projection.order.PushFront(digestBlob{key: key, data: data})
	projection.cacheBytes += len(data)
	return data, nil
}

type digestRawPayload string

func (projection *digestProjection) expand(ctx context.Context, tx *sql.Tx, value any, depth int, budget *int) (any, error) {
	if depth > 64 || ctx.Err() != nil {
		return nil, errors.New("payload depth or deadline")
	}
	switch item := value.(type) {
	case []any:
		for index := range item {
			var err error
			item[index], err = projection.expand(ctx, tx, item[index], depth+1, budget)
			if err != nil {
				return nil, err
			}
		}
	case map[string]any:
		if key, ok := item["$cpa_blob"].(string); ok {
			raw, err := projection.blob(ctx, tx, key)
			if err != nil {
				return nil, err
			}
			*budget -= len(raw)
			if *budget < 0 {
				return nil, errors.New("expanded payload limit")
			}
			switch item["encoding"] {
			case "raw":
				return digestRawPayload(raw), nil
			case "utf8":
				return string(raw), nil
			case "data-url":
				media, _ := item["media_type"].(string)
				return "data:" + media + ";base64," + base64.StdEncoding.EncodeToString(raw), nil
			case "json":
				var nested any
				if err = json.Unmarshal(raw, &nested); err != nil {
					return nil, err
				}
				return projection.expand(ctx, tx, nested, depth+1, budget)
			default:
				return nil, errors.New("unsupported payload encoding")
			}
		}
		for key := range item {
			var err error
			item[key], err = projection.expand(ctx, tx, item[key], depth+1, budget)
			if err != nil {
				return nil, err
			}
		}
	}
	return value, nil
}

func (projection *digestProjection) payload(ctx context.Context, tx *sql.Tx, reference string, legacy []byte) (any, error) {
	var raw []byte
	var err error
	if reference != "" {
		manifest, loadErr := projection.blob(ctx, tx, reference)
		if loadErr != nil {
			return nil, loadErr
		}
		var value any
		if err = json.Unmarshal(manifest, &value); err != nil {
			return nil, err
		}
		budget := maxDigestPayloadBytes
		expanded, expandErr := projection.expand(ctx, tx, value, 0, &budget)
		if expandErr != nil {
			return nil, expandErr
		}
		if original, ok := expanded.(digestRawPayload); ok {
			raw = []byte(original)
		} else {
			raw, err = json.Marshal(expanded)
		}
	} else {
		raw, err = boundedGunzip(legacy)
	}
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	if len(raw) > maxDigestPayloadBytes {
		return nil, errors.New("payload limit")
	}
	var value any
	if json.Unmarshal(raw, &value) == nil {
		return value, nil
	}
	return string(raw), nil
}

func digestTimestamp(raw string) (string, error) {
	value, err := time.Parse(time.RFC3339Nano, raw)
	return value.UTC().Format("2006-01-02T15:04:05.000000Z"), err
}

func (projection *digestProjection) record(ctx context.Context, tx *sql.Tx, sessionID, requestID string) ([]byte, error) {
	var actualRequest, actualSession, key, principal, credential, requestedModel, model, outcome string
	var started, completed, metadata, facets, originalRef, responseRef string
	var status int
	var originalLegacy, responseLegacy []byte
	var legacySize int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(length(original_request_gz),0)+COALESCE(length(response_gz),0)
		+COALESCE(length(metadata_json),0)+COALESCE(length(facets_json),0)
		FROM records WHERE request_id=? AND session_id=?`, requestID, sessionID).Scan(&legacySize); err != nil {
		return nil, err
	}
	if legacySize > maxDigestPayloadBytes {
		return nil, errors.New("legacy payload limit")
	}
	err := tx.QueryRowContext(ctx, digestRecordSQL, requestID, sessionID).Scan(&actualRequest, &actualSession,
		&key, &principal, &credential, &requestedModel, &model, &outcome, &status, &started, &completed,
		&metadata, &facets, &originalRef, &responseRef, &originalLegacy, &responseLegacy)
	if err != nil {
		return nil, err
	}
	started, err = digestTimestamp(started)
	if err != nil {
		return nil, err
	}
	completed, err = digestTimestamp(completed)
	if err != nil {
		return nil, err
	}
	item := map[string]any{"schema_version": 2, "session_id": actualSession, "request_id": actualRequest, "started_at": started, "completed_at": completed}
	for name, value := range map[string]string{"key_id": key, "principal_id": principal, "credential_hash": credential, "requested_model": requestedModel, "model": model, "outcome": outcome} {
		if strings.TrimSpace(value) != "" {
			item[name] = value
		}
	}
	if status != 0 {
		item["status_code"] = status
	}
	var metadataValue map[string]any
	if metadata != "" {
		if err = json.Unmarshal([]byte(metadata), &metadataValue); err != nil {
			return nil, err
		}
	}
	if metadataValue != nil {
		item["metadata"] = metadataValue
	}
	var facetValue map[string][]string
	if facets != "" {
		if err = json.Unmarshal([]byte(facets), &facetValue); err != nil {
			return nil, err
		}
	}
	if facetValue != nil {
		item["facets"] = facetValue
	}
	for _, payload := range []struct {
		name, reference string
		legacy          []byte
	}{{"request", originalRef, originalLegacy}, {"response", responseRef, responseLegacy}} {
		value, loadErr := projection.payload(ctx, tx, payload.reference, payload.legacy)
		if loadErr != nil {
			return nil, loadErr
		}
		if value != nil {
			item[payload.name] = value
		}
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(item); err != nil {
		return nil, err
	}
	if buffer.Len() > maxDigestPayloadBytes {
		return nil, errors.New("canonical record limit")
	}
	return buffer.Bytes(), nil
}
