// Derived from linonetwo/cpa-session-archive revision
// 7d8aec3e5301b6b33c94595a7cc466ad649cd24b under Apache-2.0.
// Modified for the MTC migration-tools release; see SOURCE.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func run(args []string, stdout, stderr io.Writer) int {
	return runWithClock(args, stdout, stderr, time.Now)
}

func runWithClock(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	flags := flag.NewFlagSet("cpa-session-archive-backup", flag.ContinueOnError)
	flags.SetOutput(stdout)
	source := flags.String("source", "", "active SQLite archive database")
	destination := flags.String("destination", "", "new backup database")
	timeout := flags.Duration("timeout", 2*time.Minute, "whole-operation timeout")
	retryInterval := flags.Duration("retry-interval", 25*time.Millisecond, "busy retry interval")
	pagesPerStep := flags.Int("pages-per-step", 1024, "SQLite pages copied between deadline checks (maximum 4096)")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, publicFailure(errInvalidArguments))
		return 2
	}
	result, err := createOnlineBackupWithProgress(context.Background(), backupOptions{
		Source:        *source,
		Destination:   *destination,
		Timeout:       *timeout,
		RetryInterval: *retryInterval,
		PagesPerStep:  *pagesPerStep,
	}, stageLogger{writer: stderr, now: now})
	if err != nil {
		fmt.Fprintln(stderr, publicFailure(err))
		return 1
	}
	if err = encodeResult(stdout, result); err != nil {
		fmt.Fprintln(stderr, publicFailure(errBackupVerification))
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
