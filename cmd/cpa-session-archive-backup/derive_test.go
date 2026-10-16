package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const digestFixtureSchema = `
CREATE TABLE records(request_id TEXT NOT NULL UNIQUE,session_id TEXT NOT NULL,key_id TEXT,principal_id TEXT,
credential_hash TEXT,requested_model TEXT,model TEXT,outcome TEXT,status_code INTEGER,started_at TEXT,completed_at TEXT,
metadata_json TEXT,facets_json TEXT,original_ref TEXT,response_ref TEXT,original_request_gz BLOB,response_gz BLOB,
upstream_ref TEXT,upstream_request_gz BLOB);
CREATE INDEX idx_records_session_time ON records(session_id,started_at);
CREATE INDEX idx_records_session_snapshot_metadata ON records(session_id,started_at,completed_at);
CREATE TABLE blobs(hash TEXT PRIMARY KEY,codec TEXT,data BLOB);
CREATE TABLE session_summaries(session_id TEXT PRIMARY KEY,requests INTEGER,first_at TEXT,last_at TEXT);
CREATE TABLE session_export_digests(session_id TEXT PRIMARY KEY,requests INTEGER,first_at TEXT,last_at TEXT,records_sha256 TEXT,max_ingest_sequence INTEGER,updated_at TEXT);
CREATE TABLE archive_ingest_events(sequence INTEGER PRIMARY KEY,session_id TEXT,previous_session_id TEXT);
CREATE INDEX idx_archive_ingest_events_session_sequence ON archive_ingest_events(session_id,sequence);
CREATE INDEX idx_archive_ingest_events_previous_session_sequence ON archive_ingest_events(previous_session_id,sequence);
CREATE TABLE archive_ingest_clock(id INTEGER PRIMARY KEY,sequence INTEGER);
CREATE TABLE archive_snapshot_contract(id INTEGER PRIMARY KEY,schema_version INTEGER);
INSERT INTO archive_snapshot_contract VALUES(1,2);`

func digestFixture(t *testing.T, count int) (string, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "derivative.sqlite")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	database, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if _, err = database.Exec(digestFixtureSchema); err != nil {
		t.Fatal(err)
	}
	compressed := digestGzip(t, []byte(`{"html":"<>&","number":9007199254740993,"null":null}`))
	for index := 0; index < count; index++ {
		_, err = database.Exec(`INSERT INTO records(request_id,session_id,started_at,completed_at,original_request_gz,metadata_json,facets_json,upstream_ref)
		VALUES(?, 'session-a','2026-01-02T03:04:05.123456789Z','2026-01-02T03:04:06Z',?,'{}','{}','unused-not-loaded')`, fmt.Sprintf("request-%06d", index), compressed)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = database.Exec(`INSERT INTO session_summaries VALUES('session-a',?,'2026-01-02T03:04:05.123456789Z','2026-01-02T03:04:06Z');
	INSERT INTO archive_ingest_clock VALUES(1,?);INSERT INTO archive_ingest_events VALUES(?,'session-a',NULL)`, count, count, count); err != nil {
		t.Fatal(err)
	}
	return path, database
}

func digestGzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func digestFixtureLine(index int) string {
	return fmt.Sprintf("{\"completed_at\":\"2026-01-02T03:04:06.000000Z\",\"facets\":{},\"metadata\":{},\"request\":{\"html\":\"<>&\",\"null\":null,\"number\":9007199254740992},\"request_id\":\"request-%06d\",\"schema_version\":2,\"session_id\":\"session-a\",\"started_at\":\"2026-01-02T03:04:05.123456Z\"}\n", index)
}

func digestTestOptions(path string, count int) digestOptions {
	return digestOptions{Work: path, WorkID: "00000000-0000-4000-8000-000000000001", ExpectedFence: int64(count), Timeout: time.Minute, CheckpointRecords: 4}
}

func TestDigestPreparationResumesInsideSessionWithoutRehash(t *testing.T) {
	path, database := digestFixture(t, 17)
	options := digestTestOptions(path, 17)
	options.MaxRecords = 7
	var total int64
	for attempt := 0; attempt < 3; attempt++ {
		result, err := prepareDigests(context.Background(), options, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		total += result.CommittedRecords
		if result.Passed != (attempt == 2) {
			t.Fatalf("unexpected result: %+v", result)
		}
		if attempt == 0 {
			var raw []byte
			if err = database.QueryRow("SELECT checkpoint FROM mtc_digest_resume_v1").Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var checkpoint digestCheckpoint
			if json.Unmarshal(raw, &checkpoint) != nil || checkpoint.Records != 7 || checkpoint.Cursor != "request-000006" {
				t.Fatal("record cursor not retained")
			}
		}
	}
	if total != 17 {
		t.Fatalf("rehashed or skipped records: %d", total)
	}
	digest := sha256.New()
	for index := 0; index < 17; index++ {
		io.WriteString(digest, digestFixtureLine(index))
	}
	var actual, first, last string
	if err := database.QueryRow("SELECT records_sha256,first_at,last_at FROM session_export_digests").Scan(&actual, &first, &last); err != nil {
		t.Fatal(err)
	}
	if actual != hex.EncodeToString(digest.Sum(nil)) || first != "2026-01-02T03:04:05.123456789Z" || last != "2026-01-02T03:04:06Z" {
		t.Fatal("official canonical digest or metadata changed")
	}
	replay, err := prepareDigests(context.Background(), options, io.Discard)
	if err != nil || !replay.Passed || replay.CommittedRecords != 0 || replay.SkippedSessions != 1 {
		t.Fatalf("committed session not skipped: %+v %v", replay, err)
	}
}

func TestDigestCompletedCoverageRejectsInconsistentSessions(t *testing.T) {
	for _, corruption := range []string{"orphan-record-session", "compensating-counts", "orphan-digest-session"} {
		t.Run(corruption, func(t *testing.T) {
			path, database := digestFixture(t, 4)
			queries := map[string]string{
				"orphan-record-session": "DELETE FROM records WHERE request_id IN ('request-000002','request-000003');UPDATE records SET session_id='session-b' WHERE request_id='request-000001';UPDATE session_summaries SET requests=2",
				"compensating-counts":   "UPDATE records SET session_id='session-b' WHERE request_id<>'request-000000';UPDATE session_summaries SET requests=2;INSERT INTO session_summaries SELECT 'session-b',2,first_at,last_at FROM session_summaries WHERE session_id='session-a'",
				"orphan-digest-session": "UPDATE session_summaries SET requests=3",
			}
			if _, err := database.Exec(queries[corruption]); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(`INSERT INTO session_export_digests
				SELECT session_id,requests,first_at,last_at,?,CASE WHEN session_id='session-a' THEN 4 ELSE 0 END,'' FROM session_summaries`, strings.Repeat("a", 64)); err != nil {
				t.Fatal(err)
			}
			if corruption == "orphan-digest-session" {
				if _, err := database.Exec(`INSERT INTO session_export_digests VALUES('session-orphan',1,'','',?,0,'')`, strings.Repeat("a", 64)); err != nil {
					t.Fatal(err)
				}
			}
			result, err := prepareDigests(context.Background(), digestTestOptions(path, 4), io.Discard)
			if err == nil || result.Passed || result.CommittedRecords != 0 || result.BlobReads != 0 || result.SkippedSessions == 0 {
				t.Fatalf("inconsistent completed coverage accepted or payload rehashed: %+v %v", result, err)
			}
		})
	}
}

func TestDigestCompletedCoverageSkipsPayloadReads(t *testing.T) {
	path, database := digestFixture(t, 2)
	options := digestTestOptions(path, 2)
	if result, err := prepareDigests(context.Background(), options, io.Discard); err != nil || !result.Passed {
		t.Fatalf("initial digest failed: %+v %v", result, err)
	}
	if _, err := database.Exec("UPDATE records SET original_ref='unreadable-payload'"); err != nil {
		t.Fatal(err)
	}
	result, err := prepareDigests(context.Background(), options, io.Discard)
	if err != nil || !result.Passed || result.SkippedSessions != 1 || result.CommittedRecords != 0 || result.BlobReads != 0 {
		t.Fatalf("completed coverage read payload: %+v %v", result, err)
	}
}

func TestDigestPagePlanAvoidsSessionSortAndScan(t *testing.T) {
	path, database := digestFixture(t, 3)
	options := digestTestOptions(path, 3)
	options.MaxRecords = 1
	if _, err := prepareDigests(context.Background(), options, io.Discard); err != nil {
		t.Fatal(err)
	}
	rows, err := database.Query("EXPLAIN QUERY PLAN "+digestPageSQL, "session-a", "request-000000", 2)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var identifier, parent, auxiliary int
		var detail string
		if err = rows.Scan(&identifier, &parent, &auxiliary, &detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, "TEMP B-TREE") || strings.Contains(detail, "SCAN records") {
			t.Fatal(detail)
		}
		found = found || strings.Contains(detail, "COVERING INDEX cpa_digest_records_v1")
	}
	if !found || rows.Err() != nil {
		t.Fatal("covering seek absent")
	}
}

func TestDigestCheckpointCorruptionAndFenceFailClosed(t *testing.T) {
	for _, corruption := range []string{"checkpoint", "fence", "count", "blob", "invalid-index", "work-id"} {
		t.Run(corruption, func(t *testing.T) {
			path, database := digestFixture(t, 3)
			options := digestTestOptions(path, 3)
			options.MaxRecords = 1
			if _, err := prepareDigests(context.Background(), options, io.Discard); err != nil {
				t.Fatal(err)
			}
			queries := map[string]string{
				"checkpoint":    "UPDATE mtc_digest_resume_v1 SET checksum='bad'",
				"fence":         "UPDATE archive_ingest_clock SET sequence=4",
				"count":         "UPDATE session_summaries SET requests=4",
				"blob":          "UPDATE records SET original_ref='missing' WHERE request_id='request-000001'",
				"invalid-index": "DROP INDEX cpa_digest_records_v1;CREATE INDEX cpa_digest_records_v1 ON records(started_at)",
				"work-id":       "UPDATE mtc_digest_binding_v1 SET identity='different-volume'",
			}
			if _, err := database.Exec(queries[corruption]); err != nil {
				t.Fatal(err)
			}
			if _, err := prepareDigests(context.Background(), options, io.Discard); err == nil {
				t.Fatal("invalid source/checkpoint accepted")
			}
			var committed int
			if err := database.QueryRow("SELECT count(*) FROM session_export_digests").Scan(&committed); err != nil || committed != 0 {
				t.Fatal("partial session published")
			}
		})
	}
}

func TestDigestProjectionCASMatchesOfficialBytesAndCachesBlobs(t *testing.T) {
	_, database := digestFixture(t, 2)
	manifest := []byte(`{"blob":{"$cpa_blob":"text","encoding":"utf8"},"raw":{"$cpa_blob":"raw","encoding":"raw"},"nested":{"$cpa_blob":"json","encoding":"json"},"image":{"$cpa_blob":"image","encoding":"data-url","media_type":"image/test"}}`)
	for key, raw := range map[string][]byte{"manifest": manifest, "text": []byte("<shared>"), "raw": []byte("plain"), "json": []byte(`{"value":9007199254740993}`), "image": {0, 255}} {
		if _, err := database.Exec("INSERT INTO blobs VALUES(?,'gzip',?)", key, digestGzip(t, raw)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec("UPDATE records SET original_ref='manifest'"); err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	projection := newDigestProjection()
	for index := 0; index < 2; index++ {
		actual, failure := projection.record(context.Background(), tx, "session-a", fmt.Sprintf("request-%06d", index))
		if failure != nil {
			t.Fatal(failure)
		}
		expected := strings.Replace(digestFixtureLine(index), `{"html":"<>&","null":null,"number":9007199254740992}`, `{"blob":"<shared>","image":"data:image/test;base64,AP8=","nested":{"value":9007199254740992},"raw":"plain"}`, 1)
		if string(actual) != expected {
			t.Fatalf("projection bytes changed: %s", actual)
		}
	}
	if projection.blobReads != 5 {
		t.Fatalf("shared blobs reread: %d", projection.blobReads)
	}
}

func TestDigestCLIActualDispatchAndPrivateErrors(t *testing.T) {
	var helpOutput, helpErrors bytes.Buffer
	if code := run([]string{"prepare-digests", "--help"}, &helpOutput, &helpErrors); code != 0 || !strings.Contains(helpOutput.String(), "checkpoint-records") || helpErrors.Len() != 0 {
		t.Fatalf("digest CLI help failed: %d %s", code, &helpErrors)
	}
	path, _ := digestFixture(t, 2)
	var stdout, stderr bytes.Buffer
	code := run([]string{"prepare-digests", "--work", path, "--work-id", "00000000-0000-4000-8000-000000000001", "--expected-fence", "2", "--checkpoint-records", "1", "--max-records", "1"}, &stdout, &stderr)
	if code != 3 || !strings.Contains(stdout.String(), "PARTIAL_CHECKPOINT_RETAINED") || !strings.Contains(stderr.String(), "DIGEST_CHECKPOINT") {
		t.Fatalf("bounded CLI result: %d %s %s", code, &stdout, &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	if code = run([]string{"prepare-digests", "--work", path, "--work-id", "00000000-0000-4000-8000-000000000001", "--expected-fence", "2"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "DIGEST_COVERAGE_PASS_NOT_SEALED") {
		t.Fatalf("resume CLI: %d %s", code, &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	if code = run([]string{"prepare-digests", "--work", path, "--work-id", "00000000-0000-4000-8000-000000000001", "--expected-fence", "3"}, &stdout, &stderr); code != 1 || strings.Contains(stderr.String(), path) || strings.Contains(stderr.String(), "session-a") {
		t.Fatal("CLI failed to redact rejection")
	}
}

type digestProgressWriter func([]byte) (int, error)

func (writer digestProgressWriter) Write(value []byte) (int, error) {
	return writer(value)
}

func TestDigestRejectsConcurrentWriterWithoutFenceUpdate(t *testing.T) {
	path, database := digestFixture(t, 3)
	options := digestTestOptions(path, 3)
	options.CheckpointRecords = 1
	mutated := false
	writer := digestProgressWriter(func(value []byte) (int, error) {
		if !mutated && bytes.Contains(value, []byte("DIGEST_CHECKPOINT")) {
			if _, err := database.Exec("UPDATE records SET outcome='changed' WHERE request_id='request-000002'"); err != nil {
				t.Fatal(err)
			}
			mutated = true
		}
		return len(value), nil
	})
	result, err := prepareDigests(context.Background(), options, writer)
	if err == nil || !mutated || result.Passed || result.CommittedRecords != 1 {
		t.Fatalf("concurrent mutation not rejected: %+v %v", result, err)
	}
}

func TestDigestCacheBoundsEvenEmptyBlobs(t *testing.T) {
	_, database := digestFixture(t, 1)
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	projection := newDigestProjection()
	for index := 0; index < 1026; index++ {
		key := fmt.Sprintf("empty-%04d", index)
		if _, err = tx.Exec("INSERT INTO blobs VALUES(?,'raw',?)", key, []byte{}); err != nil {
			t.Fatal(err)
		}
		if _, err = projection.blob(context.Background(), tx, key); err != nil {
			t.Fatal(err)
		}
	}
	if len(projection.cache) != 1024 || projection.cacheBytes != 0 || projection.cache["empty-0000"] != nil {
		t.Fatal("cache entry cap not enforced")
	}
}

func TestDigestProjectionOptionalFieldsAndRawRoot(t *testing.T) {
	_, database := digestFixture(t, 1)
	if _, err := database.Exec(`INSERT INTO blobs VALUES('root','raw',?);INSERT INTO blobs VALUES('raw','raw',?);
	UPDATE records SET original_ref='root',key_id=' key ',principal_id='principal',credential_hash='hash',requested_model='requested',model='model',outcome='ok',status_code=200,
	metadata_json='{"n":1e-7}',facets_json='{"tag":["value"]}',response_gz=?`,
		[]byte(`{"$cpa_blob":"raw","encoding":"raw"}`), []byte("event: raw\n\u2028"), digestGzip(t, []byte(`{"answer":true}`))); err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	actual, err := newDigestProjection().record(context.Background(), tx, "session-a", "request-000000")
	if err != nil {
		t.Fatal(err)
	}
	expected := "{\"completed_at\":\"2026-01-02T03:04:06.000000Z\",\"credential_hash\":\"hash\",\"facets\":{\"tag\":[\"value\"]},\"key_id\":\" key \",\"metadata\":{\"n\":1e-7},\"model\":\"model\",\"outcome\":\"ok\",\"principal_id\":\"principal\",\"request\":\"event: raw\\n\\u2028\",\"request_id\":\"request-000000\",\"requested_model\":\"requested\",\"response\":{\"answer\":true},\"schema_version\":2,\"session_id\":\"session-a\",\"started_at\":\"2026-01-02T03:04:05.123456Z\",\"status_code\":200}\n"
	if string(actual) != expected {
		t.Fatalf("optional projection differs: %s", actual)
	}
}

func TestLargeDigestCanonicalStreamingPreservesBytes(t *testing.T) {
	value := map[string]any{"body": strings.Repeat("x", 20921650), "escaped": "<>&\u2028\u2029\ufffd", "nested": []any{float64(9007199254740992), nil, true}}
	var expected, actual bytes.Buffer
	encoder := json.NewEncoder(&expected)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	if err := writeDigestJSON(context.Background(), &actual, value); err != nil {
		t.Fatal(err)
	}
	actual.WriteByte('\n')
	if !bytes.Equal(expected.Bytes(), actual.Bytes()) {
		t.Fatal("large canonical bytes changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if writeDigestJSON(ctx, io.Discard, value) == nil {
		t.Fatal("canceled record continued")
	}
}

func TestLargeDigestResumeAndCacheBound(t *testing.T) {
	path, db := digestFixture(t, 2)
	raw := []byte(`{"body":"` + strings.Repeat("x", 20921650) + `"}`)
	if _, err := db.Exec("UPDATE records SET original_request_gz=?", digestGzip(t, raw)); err != nil {
		t.Fatal(err)
	}
	options := digestTestOptions(path, 2)
	options.CheckpointRecords = 1
	options.MaxRecords = 1
	first, err := prepareDigests(context.Background(), options, io.Discard)
	if err != nil || first.Passed || first.CommittedRecords != 1 {
		t.Fatalf("large checkpoint failed: %+v %v", first, err)
	}
	second, err := prepareDigests(context.Background(), options, io.Discard)
	if err != nil || !second.Passed || second.CommittedRecords != 1 {
		t.Fatalf("large resume failed: %+v %v", second, err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	projection := newDigestProjection()
	expected := sha256.New()
	for i := 0; i < 2; i++ {
		if _, err := projection.writeRecord(context.Background(), tx, "session-a", fmt.Sprintf("request-%06d", i), expected); err != nil {
			t.Fatal(err)
		}
	}
	var actual string
	if err := tx.QueryRow("SELECT records_sha256 FROM session_export_digests").Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != hex.EncodeToString(expected.Sum(nil)) {
		t.Fatal("resumed hash differs")
	}
}

func TestDigestStringChunkBoundaries(t *testing.T) {
	for _, value := range []string{
		strings.Repeat("x", 65535) + "界<>&\u2028\u2029",
		strings.Repeat("x", 65534) + "😀界",
		strings.Repeat(string([]byte{0x80}), 131075),
		strings.Repeat("x", 65535) + string([]byte{0xe2, 0x80}) + "valid",
	} {
		var expected, actual bytes.Buffer
		encoder := json.NewEncoder(&expected)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(value); err != nil {
			t.Fatal(err)
		}
		if err := writeDigestJSON(context.Background(), &actual, value); err != nil {
			t.Fatal(err)
		}
		actual.WriteByte('\n')
		if !bytes.Equal(expected.Bytes(), actual.Bytes()) {
			t.Fatal("chunk boundary changed canonical string")
		}
	}
}

func TestLargeCASDataURLMatchesCanonicalHashWithoutCacheRetention(t *testing.T) {
	_, db := digestFixture(t, 1)
	raw := bytes.Repeat([]byte{0, 127, 255}, 6973884)
	manifest := []byte(`{"image":{"$cpa_blob":"large-image","encoding":"data-url","media_type":"image/test"}}`)
	for key, value := range map[string][]byte{"manifest": manifest, "large-image": raw} {
		if _, err := db.Exec("INSERT INTO blobs VALUES(?,'gzip',?)", key, digestGzip(t, value)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("UPDATE records SET original_ref='manifest'"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	projection := newDigestProjection()
	actual := sha256.New()
	if _, err := projection.writeRecord(context.Background(), tx, "session-a", "request-000000", actual); err != nil {
		t.Fatal(err)
	}
	expectedLine := strings.Replace(digestFixtureLine(0), `{"html":"<>&","null":null,"number":9007199254740992}`, `{"image":"data:image/test;base64,`+base64.StdEncoding.EncodeToString(raw)+`"}`, 1)
	expected := sha256.Sum256([]byte(expectedLine))
	if !bytes.Equal(expected[:], actual.Sum(nil)) {
		t.Fatal("large CAS data URL canonical hash changed")
	}
	if projection.cache["large-image"] != nil || projection.cacheBytes > digestBlobCacheBytes {
		t.Fatal("large blob escaped cache budget")
	}
}
