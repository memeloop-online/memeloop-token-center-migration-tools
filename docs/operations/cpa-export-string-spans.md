# Retained spool verification: bounded string parsing

The original CPA exporter exited at its unchanged86400-second limit while verifying completed sessions. A later read-only observation found150495 retained records and zero increment. The real SQLite query plan already uses `records_by_session`; forcing that same index is not a demonstrated fix.

The strict parser previously constructed every decoded string one character at a time, including observed20,921,650-byte text/media fields. This change scans string boundaries in native spans and decodes only escaped string tokens with the native JSON string decoder. Object parsing remains custom: decoded duplicate keys, depth, finite/safe numbers, control characters, malformed escapes and trailing input remain rejected.

The existing GHA test suite adds an observed-size synthetic string under a128MiB V8 heap, emitting only byte length/time/peak-RSS counters. Existing real SQLite exporter chunk-resume, completed-session deadline, changed projection, row tampering, internally consistent digest tampering, full JSONL and manifest tests remain unchanged and mandatory.

This is a bounded parser allocation correction, not proof that storage read amplification is solved or that the real export completes within its deadline. Do not replace the running source or skip completed-session content/digest checks. Do not reset the spool, change the source descriptor, extend budgets, create a new backup or restart blindly. After independent review/normal merge and verified official packaging, the original owner may use the same canonical paths and supported resume cursor with unchanged acceptance gates.

Schema146 importer qualification is independent PR52. This parser-only change does not modify the schema pin, product APIs, archive bytes, source format, download/output limits, identity, finance, replay or retirement requirements.
