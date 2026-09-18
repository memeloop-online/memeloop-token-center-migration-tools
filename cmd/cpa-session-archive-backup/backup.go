// Derived from linonetwo/cpa-session-archive revision
// 7d8aec3e5301b6b33c94595a7cc466ad649cd24b under Apache-2.0.
// Modified to use quick_check and emit bounded phase timings; see SOURCE.md.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/mattn/go-sqlite3"
)

const (
	backupSchemaVersion = 1
	maxPagesPerStep     = 4096
	quickCheckStatement = "PRAGMA quick_check"
)

var (
	errInvalidArguments   = errors.New("invalid arguments")
	errInvalidSource      = errors.New("source database is unavailable or invalid")
	errUnsafeDestination  = errors.New("destination already exists or is unsafe")
	errBackupFailed       = errors.New("online backup failed")
	errBackupTimeout      = errors.New("online backup timed out")
	errIntegrityCheck     = errors.New("backup quick check failed")
	errBackupVerification = errors.New("backup verification failed")
)

type backupOptions struct {
	Source        string
	Destination   string
	Timeout       time.Duration
	RetryInterval time.Duration
	PagesPerStep  int
}

type backupResult struct {
	SchemaVersion     int    `json:"schema_version"`
	Records           int64  `json:"records"`
	Sessions          int64  `json:"sessions"`
	SourceIngestFence int64  `json:"source_ingest_fence"`
	ContentSHA256     string `json:"content_sha256"`
	SizeBytes         int64  `json:"size_bytes"`
}

type stageLogger struct {
	writer io.Writer
	now    func() time.Time
}

func (logger stageLogger) run(name string, operation func() error) error {
	if logger.writer == nil {
		logger.writer = io.Discard
	}
	if logger.now == nil {
		logger.now = time.Now
	}
	started := logger.now()
	fmt.Fprintf(logger.writer, "stage=%s event=start\n", name)
	err := operation()
	event := "complete"
	if err != nil {
		event = "failed"
	}
	duration := logger.now().Sub(started)
	if duration < 0 {
		duration = 0
	}
	fmt.Fprintf(logger.writer, "stage=%s event=%s duration_ms=%d\n", name, event, duration.Milliseconds())
	return err
}

func createOnlineBackup(ctx context.Context, options backupOptions) (backupResult, error) {
	return createOnlineBackupWithProgress(ctx, options, stageLogger{writer: io.Discard, now: time.Now})
}

func createOnlineBackupWithProgress(ctx context.Context, options backupOptions, logger stageLogger) (result backupResult, err error) {
	if err = validateOptions(options); err != nil {
		return backupResult{}, err
	}
	sourceInfo, err := os.Stat(options.Source)
	if err != nil || !sourceInfo.Mode().IsRegular() {
		return backupResult{}, errInvalidSource
	}
	if _, statErr := os.Lstat(options.Destination); statErr == nil {
		return backupResult{}, errUnsafeDestination
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return backupResult{}, errUnsafeDestination
	}
	if sameResolvedPath(options.Source, options.Destination) {
		return backupResult{}, errUnsafeDestination
	}

	destinationDir := filepath.Dir(options.Destination)
	temporary, err := os.CreateTemp(destinationDir, ".cpa-session-archive-backup-*.sqlite")
	if err != nil {
		return backupResult{}, errUnsafeDestination
	}
	temporaryPath := temporary.Name()
	cleanupTemporary := true
	defer func() {
		_ = temporary.Close()
		if cleanupTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		return backupResult{}, errUnsafeDestination
	}
	if err = temporary.Close(); err != nil {
		return backupResult{}, errUnsafeDestination
	}

	backupContext, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	if err = logger.run("sqlite_backup", func() error {
		return copySQLiteOnline(backupContext, options.Source, temporaryPath, options.PagesPerStep, options.RetryInterval)
	}); err != nil {
		return backupResult{}, classifyOperationError(backupContext, err, errBackupFailed)
	}

	verification, err := openBackupDatabase(backupContext, temporaryPath)
	if err != nil {
		return backupResult{}, classifyOperationError(backupContext, err, errBackupVerification)
	}
	defer verification.Close()
	if err = logger.run("quick_check", func() error {
		return verifyQuickCheck(backupContext, verification)
	}); err != nil {
		return backupResult{}, classifyOperationError(backupContext, err, err)
	}
	if err = logger.run("archive_summary", func() error {
		result, err = inspectBackupSummary(backupContext, verification)
		return err
	}); err != nil {
		return backupResult{}, classifyOperationError(backupContext, err, errBackupVerification)
	}
	if err = verification.Close(); err != nil {
		return backupResult{}, errBackupVerification
	}

	if err = logger.run("fsync", func() error {
		return syncFile(temporaryPath)
	}); err != nil {
		return backupResult{}, errBackupVerification
	}
	if err = logger.run("sha256", func() error {
		result.ContentSHA256, result.SizeBytes, err = hashFile(backupContext, temporaryPath)
		return err
	}); err != nil {
		return backupResult{}, classifyOperationError(backupContext, err, errBackupVerification)
	}
	if err = logger.run("publish", func() error {
		if linkErr := os.Link(temporaryPath, options.Destination); linkErr != nil {
			return errUnsafeDestination
		}
		if syncErr := syncDirectory(destinationDir); syncErr != nil {
			return syncErr
		}
		if removeErr := os.Remove(temporaryPath); removeErr != nil {
			return removeErr
		}
		cleanupTemporary = false
		return syncDirectory(destinationDir)
	}); err != nil {
		if errors.Is(err, errUnsafeDestination) {
			return backupResult{}, err
		}
		return backupResult{}, errBackupVerification
	}
	return result, nil
}

func classifyOperationError(ctx context.Context, err, fallback error) error {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return errBackupTimeout
	}
	if errors.Is(err, errIntegrityCheck) {
		return errIntegrityCheck
	}
	return fallback
}

func validateOptions(options backupOptions) error {
	if options.Source == "" || options.Destination == "" || options.Timeout <= 0 || options.RetryInterval <= 0 || options.PagesPerStep <= 0 || options.PagesPerStep > maxPagesPerStep {
		return errInvalidArguments
	}
	return nil
}

func sameResolvedPath(source, destination string) bool {
	sourceAbsolute, sourceErr := filepath.Abs(source)
	destinationAbsolute, destinationErr := filepath.Abs(destination)
	if sourceErr != nil || destinationErr != nil {
		return true
	}
	return filepath.Clean(sourceAbsolute) == filepath.Clean(destinationAbsolute)
}

func sqliteFileDSN(path, mode string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	uri := &url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
	query := uri.Query()
	query.Set("mode", mode)
	query.Set("_busy_timeout", "0")
	uri.RawQuery = query.Encode()
	return uri.String(), nil
}

func copySQLiteOnline(ctx context.Context, sourcePath, destinationPath string, pagesPerStep int, retryInterval time.Duration) error {
	sourceDSN, err := sqliteFileDSN(sourcePath, "ro")
	if err != nil {
		return err
	}
	destinationDSN, err := sqliteFileDSN(destinationPath, "rw")
	if err != nil {
		return err
	}
	sourceDB, err := sql.Open("sqlite3", sourceDSN)
	if err != nil {
		return err
	}
	defer sourceDB.Close()
	sourceDB.SetMaxOpenConns(1)
	destinationDB, err := sql.Open("sqlite3", destinationDSN)
	if err != nil {
		return err
	}
	defer destinationDB.Close()
	destinationDB.SetMaxOpenConns(1)

	sourceConnection, err := acquireSQLiteConnection(ctx, sourceDB, retryInterval)
	if err != nil {
		return err
	}
	defer sourceConnection.Close()
	destinationConnection, err := acquireSQLiteConnection(ctx, destinationDB, retryInterval)
	if err != nil {
		return err
	}
	defer destinationConnection.Close()

	return sourceConnection.Raw(func(sourceDriver any) error {
		sourceSQLite, ok := sourceDriver.(*sqlite3.SQLiteConn)
		if !ok {
			return errBackupFailed
		}
		return destinationConnection.Raw(func(destinationDriver any) error {
			destinationSQLite, ok := destinationDriver.(*sqlite3.SQLiteConn)
			if !ok {
				return errBackupFailed
			}
			var backup *sqlite3.SQLiteBackup
			for {
				var backupErr error
				backup, backupErr = destinationSQLite.Backup("main", sourceSQLite, "main")
				if backupErr == nil {
					break
				}
				if !isSQLiteBusy(backupErr) {
					return backupErr
				}
				if waitErr := waitForRetry(ctx, retryInterval); waitErr != nil {
					return waitErr
				}
			}
			return stepSQLiteBackup(ctx, backup, pagesPerStep, retryInterval)
		})
	})
}

func acquireSQLiteConnection(ctx context.Context, db *sql.DB, retryInterval time.Duration) (*sql.Conn, error) {
	for {
		connection, err := db.Conn(ctx)
		if err == nil {
			return connection, nil
		}
		if !isSQLiteBusy(err) {
			return nil, err
		}
		if waitErr := waitForRetry(ctx, retryInterval); waitErr != nil {
			return nil, waitErr
		}
	}
}

func isSQLiteBusy(err error) bool {
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked
}

func waitForRetry(ctx context.Context, retryInterval time.Duration) error {
	timer := time.NewTimer(retryInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func stepSQLiteBackup(ctx context.Context, backup *sqlite3.SQLiteBackup, pagesPerStep int, retryInterval time.Duration) (err error) {
	defer func() {
		finishErr := backup.Finish()
		if err == nil {
			err = finishErr
		}
	}()
	for {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		remainingBefore := backup.Remaining()
		done, stepErr := backup.Step(pagesPerStep)
		if stepErr != nil {
			return stepErr
		}
		if done {
			return nil
		}
		remainingAfter := backup.Remaining()
		pageCountAfter := backup.PageCount()
		madeProgress := remainingAfter < remainingBefore || (remainingBefore == 0 && remainingAfter < pageCountAfter)
		if madeProgress {
			continue
		}
		if waitErr := waitForRetry(ctx, retryInterval); waitErr != nil {
			return waitErr
		}
	}
}

func openBackupDatabase(ctx context.Context, path string) (*sql.DB, error) {
	dsn, err := sqliteFileDSN(path, "ro")
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func verifyQuickCheck(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, quickCheckStatement)
	if err != nil {
		return errIntegrityCheck
	}
	checks := 0
	for rows.Next() {
		var check string
		if err = rows.Scan(&check); err != nil {
			_ = rows.Close()
			return errIntegrityCheck
		}
		checks++
		if check != "ok" {
			_ = rows.Close()
			return errIntegrityCheck
		}
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return errIntegrityCheck
	}
	if err = rows.Close(); err != nil || checks != 1 {
		return errIntegrityCheck
	}
	return nil
}

func inspectBackupSummary(ctx context.Context, db *sql.DB) (backupResult, error) {
	result := backupResult{SchemaVersion: backupSchemaVersion}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM records`).Scan(&result.Records); err != nil {
		return backupResult{}, err
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT session_id) FROM records`).Scan(&result.Sessions); err != nil {
		return backupResult{}, err
	}
	if err := db.QueryRowContext(ctx, `SELECT sequence FROM archive_ingest_clock WHERE id=1`).Scan(&result.SourceIngestFence); err != nil {
		return backupResult{}, err
	}
	return result, nil
}

func hashFile(ctx context.Context, path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 1024*1024)
	var size int64
	for {
		if err = ctx.Err(); err != nil {
			return "", 0, err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			written, writeErr := hash.Write(buffer[:read])
			size += int64(written)
			if writeErr != nil || written != read {
				return "", 0, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", 0, readErr
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func syncFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func encodeResult(writer io.Writer, result backupResult) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func publicFailure(err error) string {
	switch {
	case errors.Is(err, errInvalidArguments):
		return errInvalidArguments.Error()
	case errors.Is(err, errInvalidSource):
		return errInvalidSource.Error()
	case errors.Is(err, errUnsafeDestination):
		return errUnsafeDestination.Error()
	case errors.Is(err, errBackupTimeout):
		return errBackupTimeout.Error()
	case errors.Is(err, errIntegrityCheck):
		return errIntegrityCheck.Error()
	case errors.Is(err, errBackupVerification):
		return errBackupVerification.Error()
	default:
		return fmt.Sprint(errBackupFailed)
	}
}
