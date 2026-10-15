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
 "sort"
 "unicode/utf8"
	"time"
)

const digestRecordSQL = `SELECT request_id,session_id,COALESCE(key_id,''),COALESCE(principal_id,''),
	COALESCE(credential_hash,''),COALESCE(requested_model,''),COALESCE(model,''),COALESCE(outcome,''),
	COALESCE(status_code,0),started_at,completed_at,COALESCE(metadata_json,''),COALESCE(facets_json,''),
	COALESCE(original_ref,''),COALESCE(response_ref,''),original_request_gz,response_gz
	FROM records WHERE request_id=? AND session_id=?`

const digestBlobCacheBytes = 16 << 20

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

func decodeDigestGzip(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(&digestContextReader{ctx: ctx, reader: reader})
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
	if size < 0 {
		return nil, errors.New("blob limit")
	}
	var data []byte
	if err := tx.QueryRowContext(ctx, "SELECT data FROM blobs WHERE hash=?", key).Scan(&data); err != nil {
		return nil, err
	}
	projection.blobReads++
	if codec == "gzip" {
		var err error
		data, err = decodeDigestGzip(ctx, data)
		if err != nil {
			return nil, err
		}
	}
	// Oversize blobs are processed once, never retained in the shared cache.
 if len(data) > digestBlobCacheBytes { return data, nil }
	for (projection.cacheBytes+len(data) > digestBlobCacheBytes || projection.order.Len() >= 1024) && projection.order.Len() > 0 {
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

type digestDataURL struct { media string; data []byte }

type digestContextReader struct { ctx context.Context; reader io.Reader }
func (r *digestContextReader) Read(p []byte) (int,error) { if err:=r.ctx.Err();err!=nil{return 0,err}; return r.reader.Read(p) }

func (projection *digestProjection) expand(ctx context.Context, tx *sql.Tx, value any, depth int) (any, error) {
	if depth > 64 || ctx.Err() != nil {
		return nil, errors.New("payload depth or deadline")
	}
	switch item := value.(type) {
	case []any:
		for index := range item {
			var err error
			item[index], err = projection.expand(ctx, tx, item[index], depth+1)
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
			switch item["encoding"] {
			case "raw":
				return digestRawPayload(raw), nil
			case "utf8":
				return string(raw), nil
			case "data-url":
				media, _ := item["media_type"].(string)
				return digestDataURL{media:media,data:raw}, nil
			case "json":
				var nested any
				if err = json.Unmarshal(raw, &nested); err != nil {
					return nil, err
				}
				return projection.expand(ctx, tx, nested, depth+1)
			default:
				return nil, errors.New("unsupported payload encoding")
			}
		}
		for key := range item {
			var err error
			item[key], err = projection.expand(ctx, tx, item[key], depth+1)
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
		expanded, expandErr := projection.expand(ctx, tx, value, 0)
		if expandErr != nil {
			return nil, expandErr
		}
		if original, ok := expanded.(digestRawPayload); ok {
			raw = []byte(original)
		} else {
			// Structured expansion is already the semantic JSON value. Avoid a
 // full marshal/unmarshal round trip of large data URLs.
 return expanded, nil
		}
	} else {
		raw, err = decodeDigestGzip(ctx, legacy)
	}
	if err != nil || len(raw) == 0 {
		return nil, err
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

func (projection *digestProjection) recordValue(ctx context.Context, tx *sql.Tx, sessionID, requestID string) (any, error) {
	var actualRequest, actualSession, key, principal, credential, requestedModel, model, outcome string
	var started, completed, metadata, facets, originalRef, responseRef string
	var status int
	var originalLegacy, responseLegacy []byte
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
 return item, nil
}

// writeDigestJSON preserves encoding/json's sorted keys, float64 semantics,
// HTML policy and newline contract while avoiding a whole canonical line buffer.
// String fragments end on UTF-8 boundaries so replacement of invalid bytes and
// escaping of U+2028/U+2029 remain identical to the original encoder.
func writeDigestJSON(ctx context.Context, w io.Writer, value any) error {
 if err := ctx.Err(); err != nil { return err }
 write := func(s string) error { _, err := io.WriteString(w, s); return err }
 switch v := value.(type) {
 case digestRawPayload:
  return writeDigestJSON(ctx, w, string(v))
 case string:
  if err := write("\""); err != nil { return err }
  if err := writeDigestString(ctx,w,v); err != nil { return err }
  return write("\"")
 case digestDataURL:
  if err := write("\""); err != nil { return err }
  if err := writeDigestString(ctx,w,"data:"+v.media+";base64,"); err != nil { return err }
  encoder := base64.NewEncoder(base64.StdEncoding,w)
  if _,err := io.Copy(encoder,&digestContextReader{ctx:ctx,reader:bytes.NewReader(v.data)}); err != nil { return err }
  if err := encoder.Close(); err != nil { return err }; return write("\"")
 case map[string][]string:
  converted := make(map[string]any,len(v)); for key,item := range v { converted[key]=item }; return writeDigestJSON(ctx,w,converted)
 case []string:
  if v == nil { return write("null") }
  if err:=write("[");err!=nil{return err};for i,item:=range v {if i>0 {if err:=write(",");err!=nil{return err}};if err:=writeDigestJSON(ctx,w,item);err!=nil{return err}};return write("]")
 case map[string]any:
  keys := make([]string,0,len(v)); for k := range v { keys = append(keys,k) }; sort.Strings(keys)
  if err := write("{"); err != nil { return err }
  for i,k := range keys { if i > 0 { if err := write(","); err != nil { return err } }; if err := writeDigestJSON(ctx,w,k); err != nil { return err }; if err := write(":"); err != nil { return err }; if err := writeDigestJSON(ctx,w,v[k]); err != nil { return err } }
  return write("}")
 case []any:
  if err := write("["); err != nil { return err }; for i,item := range v { if i > 0 { if err := write(","); err != nil { return err } }; if err := writeDigestJSON(ctx,w,item); err != nil { return err } }; return write("]")
 default:
  // Small scalar/typed values (facets) retain the original encoder semantics.
  var b bytes.Buffer; e := json.NewEncoder(&b); e.SetEscapeHTML(false)
  if err := e.Encode(value); err != nil { return err }; _,err := w.Write(bytes.TrimSuffix(b.Bytes(),[]byte("\n"))); return err
 }
}

type digestCountingWriter struct { writer io.Writer; bytes int64 }
func (w *digestCountingWriter) Write(p []byte) (int,error) { n,err := w.writer.Write(p); w.bytes += int64(n); return n,err }
func (projection *digestProjection) writeRecord(ctx context.Context, tx *sql.Tx, sessionID, requestID string, output io.Writer) (int64,error) {
 item,err := projection.recordValue(ctx,tx,sessionID,requestID); if err != nil { return 0,err }
 counter := &digestCountingWriter{writer:output}
 if err = writeDigestJSON(ctx,counter,item); err == nil { _,err = counter.Write([]byte("\n")) }; return counter.bytes,err
}
// Retained for byte-contract fixtures; operational digest writes directly to SHA.
func (projection *digestProjection) record(ctx context.Context, tx *sql.Tx, sessionID, requestID string) ([]byte,error) {
 var b bytes.Buffer; _,err := projection.writeRecord(ctx,tx,sessionID,requestID,&b); return b.Bytes(),err
}

func writeDigestString(ctx context.Context,w io.Writer,v string) error {
  for len(v) > 0 {
   if err := ctx.Err(); err != nil { return err }
   n := len(v); if n > 64*1024 { n = 64*1024; start := n-1; for start > n-4 && !utf8.RuneStart(v[start]) { start-- }; _,size := utf8.DecodeRuneInString(v[start:]); if size > 1 && start+size > n { n = start } }
   var b bytes.Buffer
   e := json.NewEncoder(&b); e.SetEscapeHTML(false)
   if err := e.Encode(v[:n]); err != nil { return err }
   data := b.Bytes(); if _, err := w.Write(data[1:len(data)-2]); err != nil { return err }; v = v[n:]
  }
 return nil
}
