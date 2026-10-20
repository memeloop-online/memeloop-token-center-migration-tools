#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use rust_decimal::Decimal;

    fn validation_options(
        max_line_bytes: usize,
        max_plan_bytes: u64,
    ) -> SessionArchiveImportOptions<'static> {
        SessionArchiveImportOptions {
            input: Path::new("/archive.jsonl"),
            plan_directory: Path::new("/plan"),
            tenant_external_id: "archive-fixture",
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: "cpa-session-archive-v2",
            overlap_ms: 0,
            time_tolerance_ms: 0,
            max_line_bytes,
            max_plan_bytes,
            allow_unmapped: false,
            quarantine_unknown_identities: false,
            quarantine_tenant_binding_kind: None,
            quarantine_tenant_binding_proof: None,
            quarantine_approved_by_service_id: None,
            apply: false,
        }
    }

    #[test]
    fn import_resource_limits_accept_boundaries_and_reject_overrides() {
        for (line, plan) in [
            (1024, 1024 * 1024),
            (
                MAX_SESSION_ARCHIVE_LINE_BYTES,
                MAX_SESSION_ARCHIVE_PLAN_BYTES,
            ),
        ] {
            validate_session_archive_import_options(&validation_options(line, plan))
                .expect("compiled-in resource boundary must be accepted");
        }

        validate_session_archive_import_options(&validation_options(
            20_921_650,
            MAX_SESSION_ARCHIVE_PLAN_BYTES + 1,
        ))
        .expect("operator budgets may exceed the previous compiled ceilings");
        assert!(
            validate_session_archive_import_options(&validation_options(1023, 1024 * 1024))
                .is_err()
        );
        assert!(
            validate_session_archive_import_options(&validation_options(1024, 1024 * 1024 - 1))
                .is_err()
        );
    }

    #[tokio::test]
    async fn bounded_line_accepts_exact_limit_and_rejects_one_byte_over() {
        let exact = tempfile::NamedTempFile::new().expect("exact-limit input");
        std::fs::write(exact.path(), [vec![b'a'; 1023], vec![b'\n']].concat())
            .expect("write exact-limit input");
        let mut exact_input = ReadOnlyInput::open(exact.path()).await.expect("open input");
        let line = read_bounded_line(&mut exact_input.reader, 1024)
            .await
            .expect("exact-limit line must be accepted")
            .expect("exact-limit line");
        assert_eq!(line.len(), 1024);

        let over = tempfile::NamedTempFile::new().expect("over-limit input");
        std::fs::write(over.path(), [vec![b'a'; 1024], vec![b'\n']].concat())
            .expect("write over-limit input");
        let mut over_input = ReadOnlyInput::open(over.path()).await.expect("open input");
        let error = read_bounded_line(&mut over_input.reader, 1024)
            .await
            .expect_err("one byte over the line limit must fail");
        assert!(error.to_string().contains("exceeds 1024 bytes"));

        let large = tempfile::NamedTempFile::new().expect("large input");
        let mut bytes = vec![b'a'; 20_921_649];
        bytes.push(b'\n');
        std::fs::write(large.path(), &bytes).expect("write large input");
        let mut input = ReadOnlyInput::open(large.path())
            .await
            .expect("open large input");
        assert_eq!(
            read_bounded_line(&mut input.reader, bytes.len())
                .await
                .expect("configured large line")
                .expect("line"),
            bytes
        );
        let mut input = ReadOnlyInput::open(large.path())
            .await
            .expect("reopen large input");
        assert!(
            read_bounded_line(&mut input.reader, bytes.len() - 1)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stable_manifest_rejects_more_than_one_million_sessions_before_planning() {
        let directory = tempfile::tempdir().expect("manifest directory");
        let input = directory.path().join("too-many.jsonl");
        let manifest = directory.path().join("too-many.jsonl.manifest.json");
        std::fs::write(&input, []).expect("write empty input");
        std::fs::write(
            &manifest,
            serde_json::to_vec(&serde_json::json!({
                "version": 3,
                "output_file": "too-many.jsonl",
                "output_sha256": "a".repeat(64),
                "output_size_bytes": 0,
                "source_fingerprint": "b".repeat(64),
                "session_projection_protocol": "session-snapshot-cursor-v1",
                "session_set_sha256": "c".repeat(64),
                "snapshot_schema_version": 2,
                "source_ingest_fence": "0",
                "tombstone_safe_after_ingest_fence": "0",
                "deleted_session_count": 0,
                "prior_output_sha256": null,
                "prior_source_ingest_fence": null,
                "sequence": 1,
                "offline_full_snapshot": true,
                "session_count": MAX_STABLE_SESSION_COUNT + 1,
                "source_projection_requests": 0,
                "record_count": 0
            }))
            .expect("encode manifest"),
        )
        .expect("write manifest");

        let error = load_stable_delta_manifest(&input)
            .await
            .expect_err("oversized stable projection must fail before planning");
        assert!(error.to_string().contains("compiled-in session limit"));
    }

    #[tokio::test]
    async fn tombstone_only_plan_checks_database_size_incrementally_and_cleans_up() {
        let directory = tempfile::tempdir().expect("plan directory");
        let input_path = directory.path().join("tombstones.jsonl");
        let deleted_at = "2026-01-03T03:04:05.000000Z";
        let mut input_bytes = Vec::new();
        let mut set_bytes = Vec::from(&b"["[..]);
        for index in 0..PLAN_SIZE_CHECK_INTERVAL {
            let session_id = format!("tombstone-{index:04}-{}", "x".repeat(480));
            if index > 0 {
                set_bytes.push(b',');
            }
            set_bytes.extend(
                serde_json::to_vec(&TombstoneDigestSummary {
                    last_at: deleted_at,
                    requests: 0,
                    session_id: &session_id,
                    deleted: true,
                    deleted_at,
                })
                .expect("encode tombstone digest summary"),
            );
            input_bytes.extend(
                serde_json::to_vec(&serde_json::json!({
                    "_mtc_delta_type": "session_summary",
                    "schema_version": 2,
                    "session_id": session_id,
                    "requests": 0,
                    "last_at": deleted_at,
                    "deleted": true,
                    "deleted_at": deleted_at
                }))
                .expect("encode tombstone control"),
            );
            input_bytes.push(b'\n');
        }
        set_bytes.push(b']');
        std::fs::write(&input_path, &input_bytes).expect("write tombstone input");

        let config = crate::config::Config::for_test("sqlite::memory:".to_owned());
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect planning database");
        let archive = ArchiveStore::from_config(&config)
            .await
            .expect("create memory archive");
        let manifest = StableDeltaManifest {
            expected_output_sha256: "a".repeat(64),
            output_size_bytes: input_bytes.len() as u64,
            source_fingerprint: "b".repeat(64),
            sequence: 1,
            offline_full_snapshot: true,
            prior_output_sha256: None,
            prior_source_ingest_fence: None,
            snapshot_schema_version: 2,
            ingest_fence: 0,
            tombstone_safe_after_ingest_fence: Some(0),
            session_set_sha256: format!("{:x}", Sha256::digest(&set_bytes)),
            session_count: i64::try_from(PLAN_SIZE_CHECK_INTERVAL).expect("session count"),
            request_count: 0,
            record_count: 0,
            deleted_session_count: i64::try_from(PLAN_SIZE_CHECK_INTERVAL)
                .expect("deleted session count"),
        };
        let mut input = ReadOnlyInput::open(&input_path).await.expect("open input");
        let mut hasher = blake3::Hasher::new();
        while let Some(line) = read_bounded_line(&mut input.reader, 1024 * 1024)
            .await
            .expect("preflight read")
        {
            hasher.update(&line);
        }
        let seal = input.seal(hasher.finalize()).await.expect("seal input");
        input.rewind().await.expect("rewind input");
        let options = SessionArchiveImportOptions {
            input: &input_path,
            plan_directory: directory.path(),
            tenant_external_id: "archive-fixture",
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: "cpa-session-archive-v2",
            overlap_ms: 0,
            time_tolerance_ms: 0,
            max_line_bytes: 1024 * 1024,
            // The plan schema itself exceeds this. The assertion is that a
            // summary-only source checks during construction, not only at EOF.
            max_plan_bytes: 1,
            allow_unmapped: false,
            quarantine_unknown_identities: false,
            quarantine_tenant_binding_kind: None,
            quarantine_tenant_binding_proof: None,
            quarantine_approved_by_service_id: None,
            apply: false,
        };
        let error = match build_import_plan(
            &db,
            &archive,
            &options,
            0,
            &mut input,
            &seal,
            Some(&manifest),
        )
        .await
        {
            Ok(_) => panic!("summary-only plan must enforce its database byte budget"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("configured size limit"));
        let leftovers = std::fs::read_dir(directory.path())
            .expect("read plan directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".mtc-session-archive-plan-")
            })
            .count();
        assert_eq!(
            leftovers, 0,
            "failed plan and SQLite sidecars must be cleaned"
        );
    }

    #[test]
    fn payload_strings_restore_raw_bytes_and_objects_restore_json() {
        assert_eq!(
            payload_bytes(&Value::String("raw".into())).unwrap(),
            Some(b"raw".to_vec())
        );
        assert_eq!(
            payload_bytes(&serde_json::json!({"a": 1})).unwrap(),
            Some(br#"{"a":1}"#.to_vec())
        );
        assert_eq!(payload_bytes(&Value::Null).unwrap(), None);
    }

    #[test]
    fn invalid_sources_are_rejected() {
        assert!(validate_name("archive-v2", "source").is_ok());
        assert!(validate_name("../archive", "source").is_err());
    }

    #[test]
    fn archive_schema_uses_only_its_verified_identity_field() {
        let v1: ArchiveRecord = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "session_id": "s",
            "request_id": "r",
            "started_at": "2026-08-12T00:00:00Z",
            "completed_at": "2026-08-12T00:00:01Z",
            "key_id": "a".repeat(64),
            "credential_hash": "b".repeat(64)
        }))
        .expect("schema-v1 fixture");
        assert_eq!(archived_credential_hash(&v1).unwrap(), Some("a".repeat(64)));

        let v2: ArchiveRecord = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "session_id": "s",
            "request_id": "r",
            "started_at": "2026-08-12T00:00:00Z",
            "completed_at": "2026-08-12T00:00:01Z",
            "key_id": "a".repeat(64),
            "credential_hash": "b".repeat(64),
            "principal_id": "untrusted-source-principal"
        }))
        .expect("schema-v2 fixture");
        assert_eq!(archived_credential_hash(&v2).unwrap(), Some("b".repeat(64)));

        let v2_prefixed: ArchiveRecord = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "session_id": "s",
            "request_id": "r",
            "started_at": "2026-08-12T00:00:00Z",
            "completed_at": "2026-08-12T00:00:01Z",
            "key_id": "human-label",
            "principal_id": "another-untrusted-source-principal",
            "credential_hash": format!("sha256:{}", "A".repeat(64))
        }))
        .expect("prefixed schema-v2 fixture");
        assert_eq!(
            archived_credential_hash(&v2_prefixed).unwrap(),
            Some("a".repeat(64))
        );

        let v2_legacy_fallback: ArchiveRecord = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "session_id": "s",
            "request_id": "r",
            "started_at": "2026-08-12T00:00:00Z",
            "completed_at": "2026-08-12T00:00:01Z",
            "key_id": "c".repeat(64)
        }))
        .expect("schema-v2 legacy fallback fixture");
        assert_eq!(
            archived_credential_hash(&v2_legacy_fallback).unwrap(),
            Some("c".repeat(64))
        );

        let v2_invalid_explicit: ArchiveRecord = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "session_id": "s",
            "request_id": "r",
            "started_at": "2026-08-12T00:00:00Z",
            "completed_at": "2026-08-12T00:00:01Z",
            "key_id": "c".repeat(64),
            "credential_hash": "invalid-explicit-value"
        }))
        .expect("schema-v2 invalid explicit fixture");
        assert!(archived_credential_hash(&v2_invalid_explicit).is_err());

        let v2_unknown_prefix: ArchiveRecord = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "session_id": "s",
            "request_id": "r",
            "started_at": "2026-08-12T00:00:00Z",
            "completed_at": "2026-08-12T00:00:01Z",
            "key_id": "c".repeat(64),
            "credential_hash": format!("SHA256:{}", "d".repeat(64))
        }))
        .expect("unknown prefix schema-v2 fixture");
        assert!(archived_credential_hash(&v2_unknown_prefix).is_err());

        let invalid_v1: ArchiveRecord = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "session_id": "s",
            "request_id": "r",
            "started_at": "2026-08-12T00:00:00Z",
            "completed_at": "2026-08-12T00:00:01Z",
            "key_id": "human-label",
            "credential_hash": "b".repeat(64)
        }))
        .expect("invalid schema-v1 fixture");
        assert!(archived_credential_hash(&invalid_v1).is_err());
    }

    #[test]
    fn rust_schema_v2_set_digest_matches_go_golden_and_ascii_boundaries() {
        let present = serde_json::to_vec(&PresentDigestSummary {
            first_at: "2026-01-02T03:04:05.000000Z",
            last_at: "2026-01-02T03:05:06.000000Z",
            records_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            requests: 2,
            session_id: "Z",
        })
        .unwrap();
        let tombstone = serde_json::to_vec(&TombstoneDigestSummary {
            last_at: "2026-01-03T03:04:05.000000Z",
            requests: 0,
            session_id: "a",
            deleted: true,
            deleted_at: "2026-01-03T03:04:05.000000Z",
        })
        .unwrap();
        let mut digest = Sha256::new();
        digest.update(b"[");
        digest.update(present);
        digest.update(b",");
        digest.update(tombstone);
        digest.update(b"]");
        assert_eq!(
            format!("{:x}", digest.finalize()),
            "0a0b2faaba791ab3d356fe3e143119e94f09a801c47e5c2b102912535a88505b"
        );

        for session_id in [" ", "~", "contains space"] {
            let line = serde_json::to_vec(&serde_json::json!({
                "_mtc_delta_type":"session_summary","schema_version":2,"session_id":session_id,
                "requests":0,"last_at":"2026-01-03T03:04:05.000000Z","deleted":true,
                "deleted_at":"2026-01-03T03:04:05.000000Z"
            }))
            .unwrap();
            assert!(matches!(
                parse_archive_line(&line).unwrap(),
                Some(ParsedArchiveLine::Summary(_))
            ));
        }
        for session_id in ["\u{1f}", "\u{7f}"] {
            let line = serde_json::to_vec(&serde_json::json!({
                "_mtc_delta_type":"session_summary","schema_version":2,"session_id":session_id,
                "requests":0,"last_at":"2026-01-03T03:04:05.000000Z","deleted":true,
                "deleted_at":"2026-01-03T03:04:05.000000Z"
            }))
            .unwrap();
            assert!(parse_archive_line(&line).is_err());
        }
    }

    async fn snapshot_test_database() -> (tempfile::TempDir, Database, String, String) {
        let directory = tempfile::tempdir().unwrap();
        let database_url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("snapshot.sqlite").display()
        );
        let db = Database::connect(&database_url).await.unwrap();
        db.migrate().await.unwrap();
        let tenant = format!("snapshot-v2-{}", Uuid::now_v7());
        db.create_key(
            crate::db::CreateKeyInput {
                tenant_external_id: tenant.clone(),
                principal_external_id: "snapshot-principal".into(),
                alias: "Snapshot".into(),
                currency: "USD".into(),
                policy: KeyPolicy::default(),
                initial_balance: Decimal::ZERO,
                idempotency_key: Some("snapshot-key".into()),
            },
            b"snapshot-pepper",
        )
        .await
        .unwrap();
        (directory, db, tenant, database_url)
    }

    #[tokio::test]
    async fn snapshot_summary_and_tombstone_checkpoint_replay_atomically() {
        let (_directory, db, tenant, database_url) = snapshot_test_database().await;
        let present = SessionArchivePresentSummaryInput {
            source_session_id: "present".into(),
            requests: 1,
            first_at_ms: 10,
            last_at_ms: 20,
            records_sha256: "1".repeat(64),
        };
        let initial = db
            .apply_session_archive_snapshot(SessionArchiveSnapshotApplyInput {
                tenant_external_id: &tenant,
                archive_source: "archive-v2",
                snapshot_schema_version: 2,
                ingest_fence: 1,
                source_fingerprint: &"a".repeat(64),
                sequence: 1,
                offline_full_snapshot: true,
                output_sha256: &"b".repeat(64),
                prior_output_sha256: None,
                prior_source_ingest_fence: None,
                tombstone_safe_after_ingest_fence: Some(0),
                session_set_sha256: &"2".repeat(64),
                session_count: 1,
                request_count: 1,
                deleted_session_count: 0,
                staged_batch_id: None,
                legacy_checkpoint: Some(SessionArchiveLegacyCheckpointInput {
                    watermark_ms: 20,
                    watermark_request_id: "request",
                    imported_records: 1,
                }),
                present_summaries: std::slice::from_ref(&present),
                tombstones: &[],
            })
            .await
            .unwrap();
        assert!(!initial.replayed);
        let replay = db
            .apply_session_archive_snapshot(SessionArchiveSnapshotApplyInput {
                tenant_external_id: &tenant,
                archive_source: "archive-v2",
                snapshot_schema_version: 2,
                ingest_fence: 1,
                source_fingerprint: &"a".repeat(64),
                sequence: 1,
                offline_full_snapshot: true,
                output_sha256: &"b".repeat(64),
                prior_output_sha256: None,
                prior_source_ingest_fence: None,
                tombstone_safe_after_ingest_fence: Some(0),
                session_set_sha256: &"2".repeat(64),
                session_count: 1,
                request_count: 1,
                deleted_session_count: 0,
                staged_batch_id: None,
                legacy_checkpoint: Some(SessionArchiveLegacyCheckpointInput {
                    watermark_ms: 20,
                    watermark_request_id: "request",
                    imported_records: 1,
                }),
                present_summaries: std::slice::from_ref(&present),
                tombstones: &[],
            })
            .await
            .unwrap();
        assert!(replay.replayed);
        let tombstone = SessionArchiveTombstoneInput {
            source_session_id: "present".into(),
            deleted_at_ms: 30,
        };
        let deleted = db
            .apply_session_archive_snapshot(SessionArchiveSnapshotApplyInput {
                tenant_external_id: &tenant,
                archive_source: "archive-v2",
                snapshot_schema_version: 2,
                ingest_fence: 2,
                source_fingerprint: &"a".repeat(64),
                sequence: 2,
                offline_full_snapshot: false,
                output_sha256: &"c".repeat(64),
                prior_output_sha256: Some(&"b".repeat(64)),
                prior_source_ingest_fence: Some(1),
                tombstone_safe_after_ingest_fence: Some(0),
                session_set_sha256: &"3".repeat(64),
                session_count: 1,
                request_count: 0,
                deleted_session_count: 1,
                staged_batch_id: None,
                legacy_checkpoint: None,
                present_summaries: &[],
                tombstones: std::slice::from_ref(&tombstone),
            })
            .await
            .unwrap();
        assert_eq!(
            (deleted.tombstones_applied, deleted.deleted_records),
            (1, 0)
        );
        let pool = sqlx::AnyPool::connect(&database_url).await.unwrap();
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_source_sessions")
                .fetch_one(&pool)
                .await
                .unwrap();
        let fence: i64 =
            sqlx::query_scalar("SELECT ingest_fence FROM session_archive_snapshot_checkpoints")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((remaining, fence), (0, 2));
    }

    #[tokio::test]
    async fn tombstone_target_conflict_rolls_back_summary_delete_ledger_and_checkpoint() {
        let (_directory, db, tenant, database_url) = snapshot_test_database().await;
        let pool = sqlx::AnyPool::connect(&database_url).await.unwrap();
        let tenant_id: String = sqlx::query_scalar("SELECT id FROM tenants WHERE external_id=$1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO session_archive_import_records (tenant_id,source,external_request_id,target_request_id,external_event_hash,record_digest,source_started_at,imported_at,source_session_id) VALUES ($1,'archive-v2','external','00000000-0000-0000-0000-000000000001',$2,$3,1,1,'doomed')")
            .bind(&tenant_id).bind("4".repeat(64)).bind("5".repeat(64)).execute(&pool).await.unwrap();
        let tombstone = SessionArchiveTombstoneInput {
            source_session_id: "doomed".into(),
            deleted_at_ms: 30,
        };
        assert!(
            db.apply_session_archive_snapshot(SessionArchiveSnapshotApplyInput {
                tenant_external_id: &tenant,
                archive_source: "archive-v2",
                snapshot_schema_version: 2,
                ingest_fence: 2,
                source_fingerprint: &"a".repeat(64),
                sequence: 1,
                offline_full_snapshot: true,
                output_sha256: &"d".repeat(64),
                prior_output_sha256: None,
                prior_source_ingest_fence: None,
                tombstone_safe_after_ingest_fence: Some(0),
                session_set_sha256: &"6".repeat(64),
                session_count: 1,
                request_count: 0,
                deleted_session_count: 1,
                staged_batch_id: None,
                legacy_checkpoint: None,
                present_summaries: &[],
                tombstones: std::slice::from_ref(&tombstone),
            })
            .await
            .is_err()
        );
        let checkpoints: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_snapshot_checkpoints")
                .fetch_one(&pool)
                .await
                .unwrap();
        let tombstones: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_applied_tombstones")
                .fetch_one(&pool)
                .await
                .unwrap();
        let sessions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM session_archive_source_sessions")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((checkpoints, tombstones, sessions), (0, 0, 0));
        let source_record: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM session_archive_import_records WHERE source_session_id='doomed'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(source_record, 1);
    }

    #[test]
    fn request_path_enriches_metadata_without_changing_legacy_record_digest() {
        let without_path = serde_json::json!({
            "schema_version": 2,
            "session_id": "s",
            "request_id": "r",
            "started_at": "2026-08-12T00:00:00Z",
            "completed_at": "2026-08-12T00:00:01Z",
            "credential_hash": "a".repeat(64),
            "requested_model": "gpt-fixture"
        });
        let mut with_path = without_path.clone();
        with_path["request_path"] = Value::String("/v1/responses".into());
        let (without_record, without_digest) =
            parse_record(format!("{}\n", serde_json::to_string(&without_path).unwrap()).as_bytes())
                .unwrap()
                .unwrap();
        let (with_record, with_digest) =
            parse_record(format!("{}\n", serde_json::to_string(&with_path).unwrap()).as_bytes())
                .unwrap()
                .unwrap();
        assert_eq!(
            without_digest,
            digest(&serde_json::to_vec(&without_record).unwrap()),
            "streaming canonical hashing must match the legacy buffered encoding"
        );
        assert_eq!(without_digest, with_digest);
        assert_eq!(archive_protocol(&without_record), "session-archive");
        assert_eq!(archive_protocol(&with_record), "/v1/responses");
    }

    #[tokio::test]
    async fn sealed_input_rejects_in_place_changes() {
        let mut file = tempfile::NamedTempFile::new().expect("temporary input");
        file.write_all(b"first sealed content\n")
            .expect("write input");
        file.flush().expect("flush input");

        let mut input = ReadOnlyInput::open(file.path()).await.expect("open input");
        let line = read_bounded_line(&mut input.reader, 1024)
            .await
            .expect("read input")
            .expect("one line");
        let seal = input.seal(blake3::hash(&line)).await.expect("seal input");

        std::fs::write(file.path(), b"changed input bytes\n").expect("mutate input");
        let error = input
            .rewind()
            .await
            .expect_err("changed input must not be reused");
        assert!(error.to_string().contains("changed after preflight"));
        assert_eq!(seal.digest, blake3::hash(b"first sealed content\n"));
    }

    #[tokio::test]
    async fn sealed_input_rejects_path_replacement_and_digest_mismatch() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("archive.jsonl");
        std::fs::write(&path, b"sealed\n").expect("write input");
        let mut input = ReadOnlyInput::open(&path).await.expect("open input");
        let line = read_bounded_line(&mut input.reader, 1024)
            .await
            .expect("read input")
            .expect("one line");
        let seal = input.seal(blake3::hash(&line)).await.expect("seal input");

        input
            .verify_seal(&seal, blake3::hash(b"different\n"))
            .await
            .expect_err("whole-file digest mismatch must fail");

        let replacement = directory.path().join("replacement.jsonl");
        std::fs::write(&replacement, b"sealed\n").expect("write replacement");
        std::fs::rename(&replacement, &path).expect("replace input path");
        let error = input
            .verify_identity()
            .await
            .expect_err("path replacement must fail");
        assert!(error.to_string().contains("changed after preflight"));
    }

    #[tokio::test]
    async fn sealed_input_rejects_changes_during_the_planning_scan() {
        let mut file = tempfile::NamedTempFile::new().expect("temporary input");
        file.write_all(b"first\nsecond\n").expect("write input");
        file.flush().expect("flush input");

        let mut input = ReadOnlyInput::open(file.path()).await.expect("open input");
        let mut preflight_hasher = blake3::Hasher::new();
        while let Some(line) = read_bounded_line(&mut input.reader, 1024)
            .await
            .expect("preflight read")
        {
            preflight_hasher.update(&line);
        }
        let seal = input
            .seal(preflight_hasher.finalize())
            .await
            .expect("seal input");
        input.rewind().await.expect("start planning scan");

        let mut apply_hasher = blake3::Hasher::new();
        let first = read_bounded_line(&mut input.reader, 1024)
            .await
            .expect("first planning read")
            .expect("first planning line");
        apply_hasher.update(&first);
        file.write_all(b"changed-during-apply\n")
            .expect("append during planning");
        file.flush().expect("flush mutation");
        while let Some(line) = read_bounded_line(&mut input.reader, 1024)
            .await
            .expect("remaining planning read")
        {
            apply_hasher.update(&line);
        }
        let error = input
            .verify_seal(&seal, apply_hasher.finalize())
            .await
            .expect_err("mid-planning mutation must fail final verification");
        assert!(error.to_string().contains("changed after preflight"));
    }

    async fn empty_sealed_test_plan(directory: &Path) -> SealedImportPlan {
        let (guard, mut connection) = create_import_plan(directory)
            .await
            .expect("create test plan");
        create_import_plan_schema(&mut connection)
            .await
            .expect("create test plan schema");
        connection.close().await.expect("close test plan");
        seal_import_plan(guard, 0, 16 * 1024 * 1024)
            .await
            .expect("seal test plan")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sealed_plan_rejects_permission_content_and_path_tampering() {
        let directory = tempfile::tempdir().expect("test plan directory");

        let permission_plan = empty_sealed_test_plan(directory.path()).await;
        tokio::fs::set_permissions(
            &permission_plan.path.path,
            std::fs::Permissions::from_mode(0o600),
        )
        .await
        .expect("make plan writable");
        verify_plan_file(&permission_plan)
            .await
            .expect_err("a writable plan must fail closed");

        let content_plan = empty_sealed_test_plan(directory.path()).await;
        tokio::fs::set_permissions(
            &content_plan.path.path,
            std::fs::Permissions::from_mode(0o600),
        )
        .await
        .expect("make content plan writable");
        let mut content = std::fs::OpenOptions::new()
            .write(true)
            .open(&content_plan.path.path)
            .expect("open plan for tamper");
        content.write_all(b"tamper").expect("tamper plan content");
        content.flush().expect("flush plan tamper");
        drop(content);
        tokio::fs::set_permissions(
            &content_plan.path.path,
            std::fs::Permissions::from_mode(0o400),
        )
        .await
        .expect("restore read-only mode");
        verify_plan_file(&content_plan)
            .await
            .expect_err("content-tampered plan must fail closed");

        let path_plan = empty_sealed_test_plan(directory.path()).await;
        let replacement_bytes = std::fs::read(&path_plan.path.path).expect("read sealed plan");
        let displaced = directory.path().join("displaced-plan.sqlite");
        std::fs::rename(&path_plan.path.path, &displaced).expect("displace sealed plan");
        std::fs::write(&path_plan.path.path, replacement_bytes).expect("replace plan path");
        std::fs::set_permissions(&path_plan.path.path, std::fs::Permissions::from_mode(0o400))
            .expect("make replacement read-only");
        verify_plan_file(&path_plan)
            .await
            .expect_err("path-replaced plan must fail closed");
        std::fs::remove_file(displaced).expect("remove displaced plan");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn validated_plan_is_unlinked_before_database_apply() {
        let directory = tempfile::tempdir().expect("test plan directory");
        let mut source = tempfile::NamedTempFile::new().expect("test source");
        source.write_all(b"sealed source\n").expect("write source");
        source.flush().expect("flush source");
        let mut input = ReadOnlyInput::open(source.path())
            .await
            .expect("open source");
        let line = read_bounded_line(&mut input.reader, 1024)
            .await
            .expect("read source")
            .expect("source line");
        let source_seal = input.seal(blake3::hash(&line)).await.expect("seal source");
        let options = SessionArchiveImportOptions {
            input: source.path(),
            plan_directory: directory.path(),
            tenant_external_id: "archive-fixture",
            cpamp_source: "cpamp-usage-events-v1",
            archive_source: "unlink-test",
            overlap_ms: 0,
            time_tolerance_ms: 0,
            max_line_bytes: 1024,
            max_plan_bytes: 16 * 1024 * 1024,
            allow_unmapped: false,
            quarantine_unknown_identities: false,
            quarantine_tenant_binding_kind: None,
            quarantine_tenant_binding_proof: None,
            quarantine_approved_by_service_id: None,
            apply: true,
        };
        let (guard, mut connection) = create_import_plan(directory.path())
            .await
            .expect("create valid plan");
        create_import_plan_schema(&mut connection)
            .await
            .expect("create valid plan schema");
        let header = ImportPlanHeader {
            version: IMPORT_PLAN_VERSION,
            tenant_external_id: options.tenant_external_id.to_owned(),
            cpamp_source: options.cpamp_source.to_owned(),
            archive_source: options.archive_source.to_owned(),
            source_size_bytes: source_seal.identity.size,
            source_blake3: source_seal.digest.to_hex().to_string(),
            record_count: 0,
            tombstone_count: 0,
            stable_snapshot: None,
            quarantine_records: 0,
            quarantine_batch_id: None,
            tenant_binding_kind: None,
            tenant_binding_proof: None,
            approved_by_service_id: None,
        };
        sqlx::query("INSERT INTO import_plan_metadata (singleton, header_json) VALUES (1, $1)")
            .bind(serde_json::to_vec(&header).expect("encode header"))
            .execute(&mut connection)
            .await
            .expect("insert valid plan header");
        connection.close().await.expect("close valid plan");
        let writer_options = SqliteConnectOptions::new()
            .filename(&guard.path)
            .create_if_missing(false)
            .journal_mode(SqliteJournalMode::Delete);
        let mut preopened_writer = SqliteConnection::connect_with(&writer_options)
            .await
            .expect("preopen a competing SQLite writer");
        sqlx::query("PRAGMA busy_timeout = 50")
            .execute(&mut preopened_writer)
            .await
            .expect("bound competing writer wait");
        let sealed = seal_import_plan(guard, 0, options.max_plan_bytes)
            .await
            .expect("seal valid plan");
        let path = sealed.path.path.clone();
        let validated = open_validated_plan(sealed, &options, &source_seal)
            .await
            .expect("open validated plan");
        assert!(
            !path.exists(),
            "validated plan path must be unlinked before apply"
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            sqlx::query("UPDATE import_plan_metadata SET header_json = X'00' WHERE singleton = 1")
                .execute(&mut preopened_writer),
        )
        .await
        .expect("competing writer must not wait indefinitely")
        .expect_err("validated read snapshot must reject a preopened SQLite writer");
        preopened_writer
            .close()
            .await
            .expect("close competing writer");
        validated
            .connection
            .close()
            .await
            .expect("close validated plan");
    }
}
