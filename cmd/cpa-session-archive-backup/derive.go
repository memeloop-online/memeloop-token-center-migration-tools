package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const digestIndexSQL = `CREATE INDEX IF NOT EXISTS cpa_digest_records_v1 ON records(session_id COLLATE BINARY,request_id COLLATE BINARY)`
const digestPageSQL = `SELECT request_id FROM records INDEXED BY cpa_digest_records_v1
	WHERE session_id=? COLLATE BINARY AND request_id>? COLLATE BINARY ORDER BY request_id COLLATE BINARY LIMIT ?`
const digestFenceSQL = `SELECT MAX(COALESCE((SELECT MAX(sequence) FROM archive_ingest_events WHERE session_id=?),0),
	COALESCE((SELECT MAX(sequence) FROM archive_ingest_events WHERE previous_session_id=?),0))`
const digestCheckpointSchema = `CREATE TABLE IF NOT EXISTS mtc_digest_resume_v1(
	session_id TEXT PRIMARY KEY,checkpoint BLOB NOT NULL,checksum TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS mtc_digest_binding_v1(id INTEGER PRIMARY KEY CHECK(id=1),identity TEXT NOT NULL,fence INTEGER NOT NULL)`

type digestOptions struct {
	Work              string
	ExpectedFence     int64
	Timeout           time.Duration
	CheckpointRecords int
	MaxRecords        int64
}

type digestResult struct {
	Stage             string `json:"stage"`
	Passed            bool   `json:"passed"`
	CommittedSessions int64  `json:"committed_sessions"`
	SkippedSessions   int64  `json:"skipped_sessions"`
	CommittedRecords  int64  `json:"committed_records_this_run"`
	CanonicalBytes    int64  `json:"canonical_bytes_this_run"`
	BlobReads         int64  `json:"blob_reads_this_run"`
}

type digestCheckpoint struct {
	Version  int    `json:"version"`
	Session  string `json:"session"`
	Fence    int64  `json:"fence"`
	Expected int64  `json:"expected"`
	First    string `json:"first"`
	Last     string `json:"last"`
	Cursor   string `json:"cursor"`
	Records  int64  `json:"records"`
	Bytes    int64  `json:"bytes"`
	State    []byte `json:"state"`
}

type digestSession struct {
	ID       string
	Requests int64
}

func runDigestPreparation(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("prepare-digests", flag.ContinueOnError)
	flags.SetOutput(stdout)
	var options digestOptions
	flags.StringVar(&options.Work, "work", "", "isolated writable derivative only; never the original source")
	flags.Int64Var(&options.ExpectedFence, "expected-fence", -1, "required frozen ingest fence")
	flags.DurationVar(&options.Timeout, "timeout", 25*time.Minute, "bounded work duration, at most 30m")
	flags.IntVar(&options.CheckpointRecords, "checkpoint-records", 64, "atomic checkpoint interval, 1..128 records")
	flags.Int64Var(&options.MaxRecords, "max-records", 0, "optional bounded records per invocation; zero uses time limit")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "digest preparation: invalid arguments")
		return 2
	}
	result, err := prepareDigests(context.Background(), options, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "stage=%s digest preparation failed; retained committed checkpoints; no acceptance\n", result.Stage)
		return 1
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return 1
	}
	if !result.Passed {
		return 3
	}
	return 0
}

func prepareDigests(parent context.Context, options digestOptions, progress io.Writer) (result digestResult, err error) {
	result.Stage = "PREFLIGHT"
	if !filepath.IsAbs(options.Work) || options.ExpectedFence < 0 || options.Timeout <= 0 || options.Timeout > 30*time.Minute || options.CheckpointRecords < 1 || options.CheckpointRecords > 128 || options.MaxRecords < 0 {
		return result, errInvalidArguments
	}
	metadata, err := os.Lstat(options.Work)
	resolved, resolveErr := filepath.EvalSymlinks(options.Work)
	if err != nil || resolveErr != nil || resolved != filepath.Clean(options.Work) || !metadata.Mode().IsRegular() || metadata.Mode().Perm() != 0o600 {
		return result, errInvalidSource
	}
	identity, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || identity.Uid != uint32(os.Geteuid()) || identity.Nlink != 1 {
		return result, errInvalidSource
	}
	lockFD, err := syscall.Open(options.Work+".derive.lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return result, err
	}
	lock := os.NewFile(uintptr(lockFD), "digest-lock")
	defer lock.Close()
	if err = syscall.Flock(lockFD, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return result, err
	}
	defer syscall.Flock(lockFD, syscall.LOCK_UN)
	ctx, cancel := context.WithTimeout(parent, options.Timeout)
	defer cancel()
	location := url.URL{Scheme: "file", Path: options.Work}
	database, err := sql.Open("sqlite3", location.String()+"?mode=rw&_busy_timeout=1000&_txlock=immediate&_synchronous=FULL&_cache_size=-4096&_foreign_keys=on")
	if err != nil {
		return result, err
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	connection, err := database.Conn(ctx)
	if err != nil {
		return result, err
	}
	defer connection.Close()
	if _, err = connection.ExecContext(ctx, "PRAGMA trusted_schema=OFF;PRAGMA temp_store=FILE"); err != nil {
		return result, err
	}
	var dataVersion int64
	if err = connection.QueryRowContext(ctx, "PRAGMA data_version").Scan(&dataVersion); err != nil {
		return result, err
	}
	guard := func(tx *sql.Tx) error {
		var fence, version int64
		var schema int
		if failure := tx.QueryRowContext(ctx, "SELECT sequence FROM archive_ingest_clock WHERE id=1").Scan(&fence); failure != nil {
			return failure
		}
		if failure := tx.QueryRowContext(ctx, "SELECT schema_version FROM archive_snapshot_contract WHERE id=1").Scan(&schema); failure != nil {
			return failure
		}
		if failure := tx.QueryRowContext(ctx, "PRAGMA data_version").Scan(&version); failure != nil {
			return failure
		}
		if fence != options.ExpectedFence || schema != 2 || version != dataVersion {
			return errors.New("frozen derivative changed")
		}
		return nil
	}
	tx, err := connection.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	if err = guard(tx); err != nil {
		return result, err
	}
	result.Stage = "INDEX_PREPARE"
	if progress != nil {
		fmt.Fprintln(progress, "stage=INDEX_PREPARE")
	}
	if _, err = tx.ExecContext(ctx, digestIndexSQL+";"+digestCheckpointSchema); err != nil {
		return result, err
	}
	var indexDefinition string
	if err = tx.QueryRowContext(ctx, "SELECT sql FROM sqlite_schema WHERE name='cpa_digest_records_v1'").Scan(&indexDefinition); err != nil || indexDefinition != "CREATE INDEX cpa_digest_records_v1 ON records(session_id COLLATE BINARY,request_id COLLATE BINARY)" {
		return result, errors.New("unexpected digest index")
	}
	workIdentity := fmt.Sprintf("%d:%d", identity.Dev, identity.Ino)
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO mtc_digest_binding_v1(id,identity,fence) VALUES(1,?,?)", workIdentity, options.ExpectedFence); err != nil {
		return result, err
	}
	var boundIdentity string
	var boundFence int64
	if err = tx.QueryRowContext(ctx, "SELECT identity,fence FROM mtc_digest_binding_v1 WHERE id=1").Scan(&boundIdentity, &boundFence); err != nil || boundIdentity != workIdentity || boundFence != options.ExpectedFence {
		return result, errors.New("checkpoint source binding mismatch")
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	rows, err := connection.QueryContext(ctx, "SELECT session_id,requests FROM session_summaries ORDER BY session_id COLLATE BINARY")
	if err != nil {
		return result, err
	}
	var sessions []digestSession
	for rows.Next() {
		var session digestSession
		if err = rows.Scan(&session.ID, &session.Requests); err != nil {
			rows.Close()
			return result, err
		}
		if session.ID == "" || session.Requests < 1 || len(sessions) >= 1000000 {
			rows.Close()
			return result, errors.New("invalid session catalogue")
		}
		sessions = append(sessions, session)
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return result, rowErr
	}
	projection := newDigestProjection()
	result.Stage = "DIGEST_PREPARE"
	for _, session := range sessions {
		complete := false
		for !complete {
			if ctx.Err() != nil || (options.MaxRecords > 0 && result.CommittedRecords >= options.MaxRecords) {
				result.Stage = "PARTIAL_CHECKPOINT_RETAINED"
				return result, nil
			}
			tx, err = connection.BeginTx(ctx, nil)
			if err != nil {
				return result, err
			}
			if err = guard(tx); err != nil {
				return result, err
			}
			limit := options.CheckpointRecords
			if options.MaxRecords > 0 && int64(limit) > options.MaxRecords-result.CommittedRecords {
				limit = int(options.MaxRecords - result.CommittedRecords)
			}
			var skipped bool
			var records, encoded int64
			started := time.Now()
			complete, skipped, records, encoded, err = prepareDigestChunk(ctx, tx, session, projection, limit)
			if err != nil {
				_ = tx.Rollback()
				if ctx.Err() != nil {
					result.Stage = "PARTIAL_CHECKPOINT_RETAINED"
					return result, nil
				}
				return result, err
			}
			if err = tx.Commit(); err != nil {
				return result, err
			}
			result.CommittedRecords += records
			result.CanonicalBytes += encoded
			result.BlobReads = projection.blobReads
			if skipped {
				result.SkippedSessions++
			} else if complete {
				result.CommittedSessions++
			}
			if progress != nil && !skipped {
				fmt.Fprintf(progress, "stage=DIGEST_CHECKPOINT records=%d canonical_bytes=%d elapsed_ms=%d session_complete=%t\n", records, encoded, time.Since(started).Milliseconds(), complete)
			}
		}
	}
	result.Stage = "COVERAGE_VERIFY"
	tx, err = connection.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	if err = guard(tx); err != nil {
		return result, err
	}
	var actual, expected, digestRecords, digestSessions, checkpoints int64
	for query, destination := range map[string]*int64{
		"SELECT count(*) FROM records": &actual,
		"SELECT coalesce(sum(requests),0) FROM session_summaries": &expected,
		"SELECT coalesce(sum(requests),0) FROM session_export_digests": &digestRecords,
		"SELECT count(*) FROM session_export_digests": &digestSessions,
		"SELECT count(*) FROM mtc_digest_resume_v1": &checkpoints,
	} {
		if err = tx.QueryRowContext(ctx, query).Scan(destination); err != nil {
			return result, err
		}
	}
	if actual != expected || actual != digestRecords || digestSessions != int64(len(sessions)) || checkpoints != 0 {
		return result, errors.New("incomplete digest coverage")
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	result.Stage, result.Passed = "DIGEST_COVERAGE_PASS_NOT_SEALED", true
	return result, nil
}

func prepareDigestChunk(ctx context.Context, tx *sql.Tx, session digestSession, projection *digestProjection, limit int) (complete, skipped bool, records, encoded int64, err error) {
	var fence int64
	if err = tx.QueryRowContext(ctx, digestFenceSQL, session.ID, session.ID).Scan(&fence); err != nil {
		return
	}
	var previousFence, previousCount int64
	var previousSHA string
	err = tx.QueryRowContext(ctx, "SELECT requests,max_ingest_sequence,records_sha256 FROM session_export_digests WHERE session_id=?", session.ID).Scan(&previousCount, &previousFence, &previousSHA)
	if err == nil && previousFence == fence {
		decoded, decodeErr := hex.DecodeString(previousSHA)
		if decodeErr != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != previousSHA || previousCount != session.Requests {
			err = errors.New("invalid committed digest")
			return
		}
		complete, skipped = true, true
		return
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return
	}
	err = nil
	checkpoint := digestCheckpoint{Version: 1, Session: session.ID, Fence: fence, Expected: session.Requests}
	digest := sha256.New()
	var saved []byte
	var checksum string
	loadErr := tx.QueryRowContext(ctx, "SELECT checkpoint,checksum FROM mtc_digest_resume_v1 WHERE session_id=?", session.ID).Scan(&saved, &checksum)
	if loadErr == nil {
		sum := sha256.Sum256(saved)
		if hex.EncodeToString(sum[:]) != checksum || json.Unmarshal(saved, &checkpoint) != nil || checkpoint.Version != 1 || checkpoint.Session != session.ID || checkpoint.Fence != fence || checkpoint.Expected != session.Requests || checkpoint.Records < 1 || checkpoint.Records >= checkpoint.Expected || checkpoint.Cursor == "" || checkpoint.Bytes < checkpoint.Records {
			err = errors.New("invalid resume checkpoint")
			return
		}
		if err = restoreDigestHash(digest, checkpoint); err != nil {
			return
		}
	} else if errors.Is(loadErr, sql.ErrNoRows) {
		var actual int64
		var first, last string
		err = tx.QueryRowContext(ctx, "SELECT count(*),min(started_at),max(completed_at) FROM records WHERE session_id=?", session.ID).Scan(&actual, &first, &last)
		if err != nil {
			return
		}
		if actual != session.Requests {
			err = errors.New("session count mismatch")
			return
		}
		_, err = digestTimestamp(first)
		if err != nil {
			return
		}
		_, err = digestTimestamp(last)
		if err != nil {
			return
		}
		checkpoint.First, checkpoint.Last = first, last
	} else {
		err = loadErr
		return
	}
	rows, queryErr := tx.QueryContext(ctx, digestPageSQL, session.ID, checkpoint.Cursor, limit)
	if queryErr != nil {
		err = queryErr
		return
	}
	var requestIDs []string
	for rows.Next() {
		var requestID string
		if err = rows.Scan(&requestID); err != nil {
			rows.Close()
			return
		}
		requestIDs = append(requestIDs, requestID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return
	}
	if len(requestIDs) == 0 {
		err = errors.New("session cursor/count mismatch")
		return
	}
	for _, requestID := range requestIDs {
		if requestID <= checkpoint.Cursor || ctx.Err() != nil {
			err = errors.New("session cursor or deadline")
			return
		}
		line, recordErr := projection.record(ctx, tx, session.ID, requestID)
		if recordErr != nil {
			err = recordErr
			return
		}
		_, _ = digest.Write(line)
		checkpoint.Cursor = requestID
		checkpoint.Records++
		checkpoint.Bytes += int64(len(line))
		records++
		encoded += int64(len(line))
	}
	if checkpoint.Records > checkpoint.Expected {
		err = errors.New("session overflow")
		return
	}
	if checkpoint.Records == checkpoint.Expected {
		var remaining int
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM records INDEXED BY cpa_digest_records_v1 WHERE session_id=? AND request_id>?)", session.ID, checkpoint.Cursor).Scan(&remaining); err != nil {
			return
		}
		if remaining != 0 {
			err = errors.New("session has unprocessed records")
			return
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO session_export_digests(session_id,requests,first_at,last_at,records_sha256,max_ingest_sequence,updated_at)
			VALUES(?,?,?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET requests=excluded.requests,first_at=excluded.first_at,
			last_at=excluded.last_at,records_sha256=excluded.records_sha256,max_ingest_sequence=excluded.max_ingest_sequence,updated_at=excluded.updated_at`,
			session.ID, checkpoint.Records, checkpoint.First, checkpoint.Last, hex.EncodeToString(digest.Sum(nil)), fence, time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"))
		if err != nil {
			return
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM mtc_digest_resume_v1 WHERE session_id=?", session.ID)
		complete = err == nil
		return
	}
	checkpoint.State, err = digest.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return
	}
	saved, err = json.Marshal(checkpoint)
	if err != nil {
		return
	}
	sum := sha256.Sum256(saved)
	_, err = tx.ExecContext(ctx, `INSERT INTO mtc_digest_resume_v1(session_id,checkpoint,checksum) VALUES(?,?,?)
		ON CONFLICT(session_id) DO UPDATE SET checkpoint=excluded.checkpoint,checksum=excluded.checksum`, session.ID, saved, hex.EncodeToString(sum[:]))
	return
}

func restoreDigestHash(digest hash.Hash, checkpoint digestCheckpoint) error {
	if err := digest.(encoding.BinaryUnmarshaler).UnmarshalBinary(checkpoint.State); err != nil {
		return err
	}
	if len(checkpoint.State) < 8 || binary.BigEndian.Uint64(checkpoint.State[len(checkpoint.State)-8:]) != uint64(checkpoint.Bytes) {
		return errors.New("checkpoint hash length mismatch")
	}
	return nil
}
