// Derived from linonetwo/cpa-session-archive revision
// 7d8aec3e5301b6b33c94595a7cc466ad649cd24b under Apache-2.0.
// Modified for the extracted quick-check runtime; see SOURCE.md.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestCreateOnlineBackupIncludesCommittedWALAndSafeSummary(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "active-source.sqlite")
	destination := filepath.Join(directory, "published-backup.sqlite")
	db := createTestArchive(t, source, "WAL")
	defer db.Close()
	insertTestRecord(t, db, "request-one", "session-one")
	insertTestRecord(t, db, "request-two", "session-one")
	insertTestRecord(t, db, "request-three", "session-two")
	if info, err := os.Stat(source + "-wal"); err != nil || info.Size() == 0 {
		t.Fatal("test setup did not retain an active WAL")
	}

	result, err := createOnlineBackup(context.Background(), testOptions(source, destination))
	if err != nil {
		t.Fatalf("online backup failed: %v", publicFailure(err))
	}
	if result.SchemaVersion != 1 || result.Records != 3 || result.Sessions != 2 || result.SourceIngestFence != 3 {
		t.Fatalf("unexpected safe summary: %+v", result)
	}
	contents, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal("published backup is unreadable")
	}
	sum := sha256.Sum256(contents)
	if result.ContentSHA256 != hex.EncodeToString(sum[:]) || result.SizeBytes != int64(len(contents)) {
		t.Fatal("published backup content does not match its evidence")
	}
	verify := openTestDatabase(t, destination, "ro")
	defer verify.Close()
	var records int
	if err = verify.QueryRow(`SELECT COUNT(*) FROM records`).Scan(&records); err != nil || records != 3 {
		t.Fatal("published backup omitted WAL-resident records")
	}
}

func TestRunEmitsOrderedBoundedStageTimings(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source-with-private-name.sqlite")
	destination := filepath.Join(directory, "destination-with-private-name.sqlite")
	db := createTestArchive(t, source, "WAL")
	insertTestRecord(t, db, "request-one", "session-one")
	defer db.Close()

	current := time.Unix(0, 0)
	clock := func() time.Time {
		value := current
		current = current.Add(10 * time.Millisecond)
		return value
	}
	var stdout, stderr bytes.Buffer
	code := runWithClock([]string{
		"--source", source,
		"--destination", destination,
		"--timeout", "2s",
		"--retry-interval", "1ms",
		"--pages-per-step", "1",
	}, &stdout, &stderr, clock)
	if code != 0 {
		t.Fatalf("unexpected command result: code=%d stderr=%q", code, stderr.String())
	}
	var result backupResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Records != 1 || result.Sessions != 1 {
		t.Fatal("success output is not the safe result JSON")
	}
	want := ""
	for _, stage := range []string{"sqlite_backup", "quick_check", "archive_summary", "fsync", "sha256", "publish"} {
		want += "stage=" + stage + " event=start\n"
		want += "stage=" + stage + " event=complete duration_ms=10\n"
	}
	if stderr.String() != want {
		t.Fatalf("unexpected stage log:\n%s", stderr.String())
	}
	assertDoesNotContainPaths(t, stdout.String(), source, destination, directory)
	assertDoesNotContainPaths(t, stderr.String(), source, destination, directory)
}

func TestQuickCheckContractAndCorruptDatabaseRejection(t *testing.T) {
	if quickCheckStatement != "PRAGMA quick_check" || strings.Contains(quickCheckStatement, "integrity_check") {
		t.Fatalf("unexpected bounded verification statement: %q", quickCheckStatement)
	}
	corrupt := filepath.Join(t.TempDir(), "corrupt.sqlite")
	if err := os.WriteFile(corrupt, bytes.Repeat([]byte{0xff}, 8192), 0o600); err != nil {
		t.Fatal("could not create corrupt fixture")
	}
	db, err := openBackupDatabase(context.Background(), corrupt)
	if err == nil {
		defer db.Close()
		err = verifyQuickCheck(context.Background(), db)
	}
	if err == nil {
		t.Fatal("corrupt database passed quick check")
	}
}

func TestCreateOnlineBackupRefusesExistingDestinationWithoutChangingIt(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.sqlite")
	destination := filepath.Join(directory, "do-not-overwrite.sqlite")
	db := createTestArchive(t, source, "WAL")
	insertTestRecord(t, db, "request-one", "session-one")
	if err := db.Close(); err != nil {
		t.Fatal("could not close test source")
	}
	original := []byte("must remain unchanged")
	if err := os.WriteFile(destination, original, 0o600); err != nil {
		t.Fatal("could not create protected destination")
	}

	_, err := createOnlineBackup(context.Background(), testOptions(source, destination))
	if !errors.Is(err, errUnsafeDestination) {
		t.Fatalf("expected a safe destination refusal, got %q", publicFailure(err))
	}
	after, readErr := os.ReadFile(destination)
	if readErr != nil || !bytes.Equal(after, original) {
		t.Fatal("existing destination was changed")
	}
}

func TestCreateOnlineBackupTimesOutWithoutPublishingDestination(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "busy.sqlite")
	destination := filepath.Join(directory, "should-not-exist.sqlite")
	db := createTestArchive(t, source, "DELETE")
	insertTestRecord(t, db, "request-one", "session-one")
	connection, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal("could not reserve source connection")
	}
	defer connection.Close()
	defer db.Close()
	if _, err = connection.ExecContext(context.Background(), `BEGIN EXCLUSIVE`); err != nil {
		t.Fatal("could not lock source")
	}
	defer connection.ExecContext(context.Background(), `ROLLBACK`)

	options := testOptions(source, destination)
	options.Timeout = 40 * time.Millisecond
	options.RetryInterval = 5 * time.Millisecond
	var progress bytes.Buffer
	_, err = createOnlineBackupWithProgress(context.Background(), options, stageLogger{writer: &progress, now: time.Now})
	if !errors.Is(err, errBackupTimeout) {
		t.Fatalf("expected bounded timeout, got %q", publicFailure(err))
	}
	if _, statErr := os.Stat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("timed-out backup published a destination")
	}
	if !strings.Contains(progress.String(), "stage=sqlite_backup event=failed") {
		t.Fatal("failed stage timing was not emitted")
	}
}

func TestCreateOnlineBackupRejectsUnboundedStepSize(t *testing.T) {
	options := testOptions("source", "destination")
	options.PagesPerStep = maxPagesPerStep + 1
	if err := validateOptions(options); !errors.Is(err, errInvalidArguments) {
		t.Fatal("unbounded SQLite backup step size was accepted")
	}
}

func testOptions(source, destination string) backupOptions {
	return backupOptions{
		Source:        source,
		Destination:   destination,
		Timeout:       2 * time.Second,
		RetryInterval: time.Millisecond,
		PagesPerStep:  1,
	}
}

func createTestArchive(t *testing.T, path, journalMode string) *sql.DB {
	t.Helper()
	db := openTestDatabase(t, path, "rwc")
	if _, err := db.Exec(`PRAGMA journal_mode=` + journalMode); err != nil {
		t.Fatal("could not set test journal mode")
	}
	if _, err := db.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal("could not disable automatic WAL checkpoint")
	}
	if _, err := db.Exec(`CREATE TABLE records(
		id INTEGER PRIMARY KEY,
		request_id TEXT NOT NULL UNIQUE,
		session_id TEXT NOT NULL
	);
	CREATE TABLE archive_ingest_clock(id INTEGER PRIMARY KEY, sequence INTEGER NOT NULL);
	INSERT INTO archive_ingest_clock(id, sequence) VALUES(1, 0);
	CREATE TRIGGER archive_records_insert AFTER INSERT ON records BEGIN
		UPDATE archive_ingest_clock SET sequence=sequence+1 WHERE id=1;
	END;`); err != nil {
		t.Fatal("could not create test archive")
	}
	return db
}

func openTestDatabase(t *testing.T, path, mode string) *sql.DB {
	t.Helper()
	dsn, err := sqliteFileDSN(path, mode)
	if err != nil {
		t.Fatal("could not construct test database DSN")
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatal("could not open test database")
	}
	db.SetMaxOpenConns(1)
	if err = db.Ping(); err != nil {
		db.Close()
		t.Fatal("could not connect to test database")
	}
	return db
}

func insertTestRecord(t *testing.T, db *sql.DB, requestID, sessionID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO records(request_id, session_id) VALUES(?, ?)`, requestID, sessionID); err != nil {
		t.Fatal("could not insert test record")
	}
}

func assertDoesNotContainPaths(t *testing.T, output string, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if path != "" && strings.Contains(output, path) {
			t.Fatal("command output leaked a filesystem path")
		}
	}
}
