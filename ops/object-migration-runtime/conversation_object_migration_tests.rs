use super::*;
use futures_util::StreamExt;

#[tokio::test]
async fn copy_resume_verify_and_test_cutover_preserve_exact_large_unicode_body() {
    let database_url =
        std::env::var("MTC_TEST_POSTGRES_URL").expect("isolated TEST PostgreSQL required");
    let administrative = PgPool::connect(&database_url).await.unwrap();
    let name = format!("mtc_test_{}", Uuid::now_v7().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&administrative)
        .await
        .unwrap();
    let mut url = url::Url::parse(&database_url).unwrap();
    url.set_path(&name);
    let pool = PgPool::connect(url.as_str()).await.unwrap();
    sqlx::raw_sql(
        "CREATE TABLE semantic_atoms(tenant_id TEXT NOT NULL, content_hash TEXT NOT NULL, content_json TEXT NOT NULL, PRIMARY KEY(tenant_id, content_hash));
         CREATE TABLE context_nodes(tenant_id TEXT NOT NULL, node_hash TEXT NOT NULL, parent_hash TEXT, atom_hash TEXT NOT NULL, depth BIGINT NOT NULL, PRIMARY KEY(tenant_id, node_hash));
         CREATE TABLE request_records(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, request_object TEXT, response_object TEXT);
         CREATE TABLE session_archive_import_records(tenant_id TEXT NOT NULL, source TEXT NOT NULL, external_request_id TEXT NOT NULL, request_object TEXT, response_object TEXT, previous_request_object TEXT, previous_response_object TEXT);
         CREATE TABLE session_archive_unlinked_requests(tenant_id TEXT NOT NULL, archive_request_id TEXT NOT NULL, request_object TEXT, response_object TEXT);
         CREATE TABLE session_archive_quarantine_records(tenant_id TEXT NOT NULL, id TEXT NOT NULL, request_object TEXT, response_object TEXT);
         CREATE TABLE session_archive_quarantine_record_versions(LIKE session_archive_quarantine_records INCLUDING ALL);
         CREATE TABLE conversation_media_parts(tenant_id TEXT NOT NULL, turn_id TEXT NOT NULL, part_index BIGINT NOT NULL, object_locator TEXT NOT NULL, content_blake3 TEXT NOT NULL, byte_length BIGINT NOT NULL, media_type TEXT NOT NULL DEFAULT 'application/octet-stream');
         CREATE TABLE conversation_clusters(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL);
         CREATE TABLE conversation_observations(id TEXT PRIMARY KEY, cluster_id TEXT NOT NULL, request_id TEXT NOT NULL, leaf_node_hash TEXT, agent_id TEXT, parent_agent_id TEXT);
         CREATE TABLE conversation_edges(id TEXT PRIMARY KEY, cluster_id TEXT NOT NULL, from_observation_id TEXT, to_observation_id TEXT NOT NULL, relation_kind TEXT NOT NULL, confidence_millis BIGINT NOT NULL, evidence_json TEXT NOT NULL);
         CREATE TABLE request_archive_spools(request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, reservation_id TEXT NOT NULL, state TEXT NOT NULL, chunk_count BIGINT NOT NULL, byte_count BIGINT NOT NULL);
         CREATE TABLE response_archive_spools(LIKE request_archive_spools INCLUDING ALL);
         CREATE TABLE request_archive_spool_chunks(request_id TEXT NOT NULL, seq BIGINT NOT NULL, ciphertext TEXT NOT NULL, byte_count BIGINT NOT NULL, PRIMARY KEY(request_id, seq));
         CREATE TABLE response_archive_spool_chunks(LIKE request_archive_spool_chunks INCLUDING ALL);
         CREATE TABLE conversation_semantic_payloads(request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, request_json TEXT NOT NULL);
         CREATE TABLE conversation_projection_outbox(request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, request_json TEXT NOT NULL, semantic_snapshot_json TEXT, semantic_payload_snapshot_json TEXT, key_snapshot_json TEXT, hints_json TEXT NOT NULL);",
    ).execute(&pool).await.unwrap();
    let tenant = Uuid::now_v7();
    let document = serde_json::json!({"role":"tool", "content":"工具\n".repeat(1200000), "tool_call_id":"call-1", "unknown":[1,2,3]}).to_string();
    let hash = blake3::hash(document.as_bytes()).to_hex().to_string();
    let node = memeloop_token_center::conversation::digest_parts(None, &hash);
    sqlx::query("INSERT INTO semantic_atoms VALUES ($1, $2, $3)")
        .bind(tenant.to_string())
        .bind(&hash)
        .bind(&document)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO context_nodes VALUES ($1, $2, NULL, $3, 1)")
        .bind(tenant.to_string())
        .bind(&node)
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    let branch_node = memeloop_token_center::conversation::digest_parts(Some(&node), &hash);
    sqlx::query("INSERT INTO context_nodes VALUES ($1, $2, $3, $4, 2)")
        .bind(tenant.to_string())
        .bind(&branch_node)
        .bind(&node)
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut target_config = Config::for_test(url.to_string());
    if let Ok(endpoint) = std::env::var("MTC_RUSTFS_TEST_ENDPOINT") {
        target_config.archive_backend = memeloop_token_center::config::ArchiveBackend::S3;
        target_config.s3_endpoint = Some(endpoint);
        target_config.s3_bucket = Some(std::env::var("MTC_RUSTFS_TEST_BUCKET").unwrap());
        target_config.s3_access_key = Some(std::env::var("MTC_RUSTFS_TEST_ACCESS_KEY").unwrap());
        target_config.s3_secret_key = Some(std::env::var("MTC_RUSTFS_TEST_SECRET_KEY").unwrap());
        target_config.s3_region = "us-east-1".into();
        target_config.s3_allow_http = true;
    }
    let source = ArchiveStore::from_config(&Config::for_test(url.to_string()))
        .await
        .unwrap();
    let runner = Runner {
        pool: pool.clone(),
        source: Some(source.clone()),
        target: ArchiveStore::from_config(&target_config).await.unwrap(),
        checkpoint: directory.path().join("checkpoint.json"),
        identity: "fixture".into(),
    };
    let response = Bytes::from_static(
        b"event: message\r\ndata: {\"tool_call_id\":\"call-1\"}\r\n\r\ndata: [DONE]\r\n\r\n",
    );
    source
        .put("fixture/response", response.clone())
        .await
        .unwrap();
    source
        .put("fixture/media", Bytes::from_static(b"synthetic media"))
        .await
        .unwrap();
    let raw_request_id = Uuid::now_v7();
    sqlx::query("INSERT INTO request_records VALUES ($1, $2, $3, 'fixture/response')")
        .bind(raw_request_id.to_string())
        .bind(tenant.to_string())
        .bind(format!("inline-json:{document}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO conversation_media_parts (tenant_id, turn_id, part_index, object_locator, content_blake3, byte_length) VALUES ($1, $3, 0, 'fixture/media', $2, 15)",
    )
    .bind(tenant.to_string())
    .bind(blake3::hash(b"synthetic media").to_hex().to_string())
    .bind(&hash)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO session_archive_quarantine_record_versions VALUES ($1, 'retained-quarantine', $2, 'fixture/response')")
        .bind(tenant.to_string()).bind(format!("inline-json:{document}")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO session_archive_import_records VALUES ($1, 'fixture-import', 'external-request', $2, 'fixture/response', $2, 'fixture/response')")
        .bind(tenant.to_string()).bind(format!("inline-json:{document}")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO session_archive_unlinked_requests VALUES ($1, 'unlinked-request', $2, 'fixture/response')")
        .bind(tenant.to_string()).bind(format!("inline-json:{document}")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO session_archive_quarantine_records VALUES ($1, 'quarantine-request', $2, 'fixture/response')")
        .bind(tenant.to_string()).bind(format!("inline-json:{document}")).execute(&pool).await.unwrap();
    let locators = runner
        .transfer_locators_from(&source, "fixture", false)
        .await
        .unwrap();
    assert!(!locators.verified);
    let locators = runner
        .transfer_locators_from(&source, "fixture", true)
        .await
        .unwrap();
    assert!(locators.verified);
    assert_eq!(locators.copied_rows, 13);
    assert_eq!(
        locators.copied_bytes,
        6 * document.len() as u64 + 6 * response.len() as u64 + 15
    );
    source
        .put("fixture/response", Bytes::from_static(b"changed"))
        .await
        .unwrap();
    assert!(
        runner
            .transfer_locators_from(&source, "fixture", true)
            .await
            .is_err()
    );
    let checkpoint: locators::LocatorCheckpoint = serde_json::from_reader(
        std::fs::File::open(runner.checkpoint.with_extension("locators.json")).unwrap(),
    )
    .unwrap();
    assert!(!checkpoint.verified);
    source
        .put("fixture/response", response.clone())
        .await
        .unwrap();
    assert!(
        runner
            .transfer_locators_from(&source, "fixture", true)
            .await
            .unwrap()
            .verified
    );
    let spool_request = Uuid::now_v7();
    let reservation = Uuid::now_v7();
    let pepper = b"synthetic-spool-fixture-key";
    let spool_body = b"data: {\"tool_call_id\":\"call-1\"}\n\n";
    sqlx::query("INSERT INTO response_archive_spools VALUES ($1, $2, $3, 'pending', 1, $4)")
        .bind(spool_request.to_string())
        .bind(tenant.to_string())
        .bind(reservation.to_string())
        .bind(spool_body.len() as i64)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO response_archive_spool_chunks VALUES ($1, 0, $2, $3)")
        .bind(spool_request.to_string())
        .bind(spools::fixture_cipher(
            pepper,
            tenant,
            spool_request,
            reservation,
            0,
            spool_body,
        ))
        .bind(spool_body.len() as i64)
        .execute(&pool)
        .await
        .unwrap();
    let copied_spools = runner.transfer_spools(pepper, false).await.unwrap();
    assert_eq!(copied_spools.rows, 1);
    assert_eq!(copied_spools.bytes, spool_body.len() as u64);
    assert_eq!(copied_spools.chunks, 1);
    assert!(runner.transfer_spools(pepper, true).await.unwrap().verified);
    assert!(
        runner
            .transfer_spools(b"wrong fixture key", true)
            .await
            .is_err()
    );
    let source_chunks: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM response_archive_spool_chunks")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(source_chunks, 1);
    let payload_request = Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO conversation_semantic_payloads VALUES ($1, $2, $3)")
        .bind(&payload_request)
        .bind(tenant.to_string())
        .bind(&document)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO conversation_projection_outbox VALUES ($1, $2, $3, NULL, NULL, NULL, $4)",
    )
    .bind(&payload_request)
    .bind(tenant.to_string())
    .bind(&document)
    .bind(r#"{"branch_id":"branch-1","parent_turn_id":"parent-1"}"#)
    .execute(&pool)
    .await
    .unwrap();
    let payloads = runner.transfer_payloads(false).await.unwrap();
    assert_eq!(payloads.rows, 3);
    assert!(runner.transfer_payloads(true).await.unwrap().verified);
    let retained_payload: String =
        sqlx::query_scalar("SELECT request_json FROM conversation_semantic_payloads")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained_payload, document);
    assert!(runner.cutover_test().await.is_err());
    assert!(runner.cutover_locators_test().await.is_err());
    let copied = runner.copy().await.unwrap();
    let inventory = inventory::inventory(&pool).await.unwrap();
    assert_eq!(inventory["inventory_complete"], true);
    inventory::require_complete(&inventory).unwrap();
    assert_eq!(
        inventory["fields"][0]["exact_text_bytes"],
        document.len() as u64
    );
    assert_eq!(inventory["media"]["indexed_bytes"], 15);
    assert_eq!(inventory["complete_training_fidelity_certified"], false);
    assert_eq!(copied.copied_rows, 1);
    assert_eq!(copied.copied_bytes, document.len() as u64);
    let retained: String = sqlx::query_scalar("SELECT content_json FROM semantic_atoms")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(retained, document);
    assert_eq!(
        runner.copy().await.unwrap().ordered_digest,
        copied.ordered_digest
    );
    let verified = runner.verify().await.unwrap();
    assert_eq!(verified.verified_rows, 1);
    assert_eq!(verified.verified_context_nodes, 2);
    sqlx::query("INSERT INTO conversation_clusters VALUES ('session', $1)")
        .bind(tenant.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO conversation_observations VALUES ('observation', 'session', $1, $2, 'agent-child', 'agent-parent')")
        .bind(raw_request_id.to_string()).bind(&node).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO conversation_observations VALUES ('branch-observation', 'session', $1, $2, 'agent-child', 'agent-parent')")
        .bind(raw_request_id.to_string()).bind(&branch_node).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO conversation_edges VALUES ('branch-edge', 'session', 'observation', 'branch-observation', 'fork', 1000, '{\"tool_call_id\":\"call-1\"}')")
        .execute(&pool).await.unwrap();
    let reconstructed = runner.reconstruct_dialogues(false).await.unwrap();
    assert_eq!(
        (
            reconstructed.observations,
            reconstructed.events,
            reconstructed.media
        ),
        (2, 3, 3)
    );
    assert_eq!(reconstructed.edges, 1);
    assert!(runner.reconstruct_dialogues(true).await.unwrap().verified);
    sqlx::query("UPDATE conversation_edges SET from_observation_id = 'missing-parent'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(runner.reconstruct_dialogues(true).await.is_err());
    sqlx::query("UPDATE conversation_edges SET from_observation_id = 'observation'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO conversation_edges VALUES ('orphan-edge', 'session', 'observation', 'missing-target', 'fork', 1000, '{}')")
        .execute(&pool).await.unwrap();
    assert!(runner.reconstruct_dialogues(true).await.is_err());
    sqlx::query("DELETE FROM conversation_edges WHERE id = 'orphan-edge'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(runner.reconstruct_dialogues(true).await.unwrap().verified);
    sqlx::query("UPDATE conversation_observations SET parent_agent_id = 'changed-parent'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(runner.reconstruct_dialogues(true).await.is_err());
    let failed: reconstruction::ReconstructionCheckpoint = serde_json::from_reader(
        std::fs::File::open(runner.checkpoint.with_extension("reconstruction.json")).unwrap(),
    )
    .unwrap();
    assert!(!failed.verified);
    sqlx::query("UPDATE conversation_observations SET parent_agent_id = 'agent-parent'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(runner.reconstruct_dialogues(true).await.unwrap().verified);
    assert!(
        runner.cutover_test().await.is_err(),
        "individual phase receipts cannot authorize all-source cutover"
    );
    runner
        .transfer_durable_roots(&source, "fixture", false)
        .await
        .unwrap();
    let aggregate = runner
        .verify_all_from(&source, "fixture", pepper)
        .await
        .unwrap();
    assert_eq!(aggregate["verified"], true);
    assert_eq!(aggregate["complete_training_fidelity_certified"], false);
    assert!(
        runner
            .verify_all_from(&source, "fixture", b"wrong key")
            .await
            .is_err()
    );
    assert!(
        runner.cutover_test().await.is_err(),
        "failed re-verification revokes cutover authority"
    );
    assert_eq!(
        runner
            .verify_all_from(&source, "fixture", pepper)
            .await
            .unwrap()["verified"],
        true
    );
    let completed = runner.cutover_test().await.unwrap();
    assert!(completed.cutover_complete);
    let encoded: String = sqlx::query_scalar("SELECT content_json FROM semantic_atoms")
        .fetch_one(&pool)
        .await
        .unwrap();
    let reference: ConversationBodyReference = serde_json::from_str(&encoded).unwrap();
    let mut stream = runner
        .target
        .open_stream(&reference.conversation_body_v1.object_locator, None)
        .await
        .unwrap()
        .stream;
    let mut restored = Vec::new();
    while let Some(chunk) = stream.next().await {
        restored.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(restored, document.as_bytes());
    assert_eq!(reference.chars, document.chars().count() as u64);
    assert_eq!(runner.cutover_test().await.unwrap().cutover_rows, 1);
    // Every retained/imported locator and media index must work against the
    // target, not merely the live request's independent raw-root override.
    sqlx::query("UPDATE conversation_media_parts SET content_blake3 = repeat('0', 64)")
        .execute(&pool)
        .await
        .unwrap();
    assert!(runner.cutover_locators_test().await.is_err());
    let failed: serde_json::Value = serde_json::from_reader(
        std::fs::File::open(runner.checkpoint.with_extension("locator-cutover.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(failed["complete"], false);
    sqlx::query("UPDATE conversation_media_parts SET content_blake3 = $1")
        .bind(blake3::hash(b"synthetic media").to_hex().to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE request_records SET request_object = 'inline-json:changed after verification'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(runner.cutover_locators_test().await.is_err());
    sqlx::query("UPDATE request_records SET request_object = $1")
        .bind(format!("inline-json:{document}"))
        .execute(&pool)
        .await
        .unwrap();
    let switched = runner.cutover_locators_test().await.unwrap();
    assert_eq!(switched["complete"], true);
    assert_eq!(switched["rows"], 13);
    assert_eq!(switched["source_objects_deleted"], false);
    assert_eq!(runner.cutover_locators_test().await.unwrap()["rows"], 13);
    for (table, columns) in [
        (
            "request_records",
            &["request_object", "response_object"][..],
        ),
        (
            "session_archive_import_records",
            &[
                "request_object",
                "response_object",
                "previous_request_object",
                "previous_response_object",
            ][..],
        ),
        (
            "session_archive_unlinked_requests",
            &["request_object", "response_object"][..],
        ),
        (
            "session_archive_quarantine_records",
            &["request_object", "response_object"][..],
        ),
        (
            "session_archive_quarantine_record_versions",
            &["request_object", "response_object"][..],
        ),
        ("conversation_media_parts", &["object_locator"][..]),
    ] {
        for column in columns {
            let locator: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT {column} FROM {table} WHERE tenant_id = $1"
            )))
            .bind(tenant.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(locator.starts_with(&format!("tenants/{tenant}/cas/v1/blake3/")));
            let expected = if column.contains("response") {
                response.as_ref()
            } else if *column == "object_locator" {
                b"synthetic media"
            } else {
                document.as_bytes()
            };
            assert_eq!(
                runner.target.get(&locator).await.unwrap().as_ref(),
                expected
            );
        }
    }
    assert_eq!(source.get("fixture/response").await.unwrap(), response);
    assert_eq!(
        source.get("fixture/media").await.unwrap().as_ref(),
        b"synthetic media"
    );
    // Restore this fixture's locators to exercise independent source copy
    // again below; the preceding TEST cutover never deleted those originals.
    for (table, columns) in [
        (
            "request_records",
            &["request_object", "response_object"][..],
        ),
        (
            "session_archive_import_records",
            &[
                "request_object",
                "response_object",
                "previous_request_object",
                "previous_response_object",
            ][..],
        ),
        (
            "session_archive_unlinked_requests",
            &["request_object", "response_object"][..],
        ),
        (
            "session_archive_quarantine_records",
            &["request_object", "response_object"][..],
        ),
        (
            "session_archive_quarantine_record_versions",
            &["request_object", "response_object"][..],
        ),
    ] {
        for column in columns {
            let original = if column.contains("response") {
                "fixture/response".to_owned()
            } else {
                format!("inline-json:{document}")
            };
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "UPDATE {table} SET {column} = $1"
            )))
            .bind(original)
            .execute(&pool)
            .await
            .unwrap();
        }
    }
    sqlx::query("UPDATE conversation_media_parts SET object_locator = 'fixture/media'")
        .execute(&pool)
        .await
        .unwrap();
    // Compressed historical objects must stream beyond the old 64/128 MiB
    // decoder ceilings, including through real RustFS multipart promotion.
    let mut large = source
        .start_compressed_writer("fixture/large-response")
        .await
        .unwrap();
    let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
    for _ in 0..2080 {
        large.write(chunk.clone()).await.unwrap();
    }
    let large = large.finish_staged().await.unwrap();
    let large = source
        .promote_staged_text_to_cas(tenant, &large)
        .await
        .unwrap();
    let large_id = Uuid::now_v7();
    source
        .publish_raw_capture(tenant, large_id, "response", &large)
        .await
        .unwrap();
    sqlx::query("INSERT INTO request_records VALUES ($1, $2, NULL, $3)")
        .bind(large_id.to_string())
        .bind(tenant.to_string())
        .bind(&large.object_locator)
        .execute(&pool)
        .await
        .unwrap();
    // A gap before a readable row must not prevent preservation of the rest
    // of the historical archive. Gap receipts are counted and block a green
    // verification/cutover certificate, including on resume.
    for (id, locator) in [
        ("aaa-gap", "gap://fixture/missing-original"),
        (
            "aab-metadata",
            "metadata-only-json:{\"media_archived\":false}",
        ),
        (
            "aac-provider",
            "provider-reference-json:{\"id\":\"unresolved\"}",
        ),
        ("zzz-readable", "fixture/response"),
    ] {
        sqlx::query(
            "INSERT INTO session_archive_quarantine_record_versions VALUES ($1, $2, $3, NULL)",
        )
        .bind(tenant.to_string())
        .bind(id)
        .bind(locator)
        .execute(&pool)
        .await
        .unwrap();
    }
    let gap_runner = Runner {
        pool: pool.clone(),
        source: Some(source.clone()),
        target: runner.target.clone(),
        checkpoint: directory.path().join("with-gaps.json"),
        identity: "fixture-gaps".into(),
    };
    let copied = gap_runner
        .transfer_locators_from(&source, "fixture-gaps", false)
        .await
        .unwrap();
    assert_eq!(copied.copied_rows, 15);
    assert_eq!(copied.gap_rows, 3);
    assert!(!copied.verified);
    assert_eq!(
        gap_runner
            .transfer_locators_from(&source, "fixture-gaps", false)
            .await
            .unwrap()
            .gap_rows,
        3
    );
    assert!(
        gap_runner
            .transfer_locators_from(&source, "fixture-gaps", true)
            .await
            .is_err()
    );
    let evidence: locators::LocatorCheckpoint = serde_json::from_reader(
        std::fs::File::open(gap_runner.checkpoint.with_extension("locators.json")).unwrap(),
    )
    .unwrap();
    assert_eq!((evidence.copied_rows, evidence.gap_rows), (15, 3));
    assert!(!evidence.verified);
    assert!(
        gap_runner
            .verified_locator(
                "quarantine_version_request",
                &tenant.to_string(),
                "zzz-readable"
            )
            .await
            .is_err()
    );
    let copied_large = large.clone();
    // SQL locator verification and an independently discovered source root
    // must agree on the exact compressed CAS key in either execution order.
    assert_eq!(
        gap_runner
            .transfer_durable_roots(&source, "fixture-gaps", false)
            .await
            .unwrap()
            .roots,
        1
    );
    assert!(
        gap_runner
            .transfer_durable_roots(&source, "fixture-gaps", true)
            .await
            .unwrap()
            .verified
    );
    assert_eq!(
        runner
            .target
            .raw_capture_reference(tenant, large_id, "response")
            .await
            .unwrap()
            .unwrap(),
        large
    );
    assert!(copied_large.size_bytes > 128 * 1024 * 1024);
    runner
        .target
        .verify_tenant_content(tenant, &copied_large)
        .await
        .unwrap();
    let mut retained = source
        .open_stream(&large.object_locator, None)
        .await
        .unwrap()
        .stream;
    let mut retained_digest = blake3::Hasher::new();
    let mut retained_bytes = 0_u64;
    while let Some(chunk) = retained.next().await {
        let chunk = chunk.unwrap();
        retained_digest.update(&chunk);
        retained_bytes += chunk.len() as u64;
    }
    assert_eq!(retained_bytes, large.size_bytes);
    assert_eq!(
        retained_digest.finalize().to_hex().as_str(),
        large.blake3_digest
    );
    // This is only the disposable fixture database. Historical source absence
    // must preserve all readable counts, expose unknown media and revoke even
    // a previously green aggregate before attempting any transfer phase.
    let before_missing_table = inventory::inventory(&pool).await.unwrap();
    sqlx::query("DROP TABLE conversation_media_parts")
        .execute(&pool)
        .await
        .unwrap();
    let partial = inventory::inventory(&pool).await.unwrap();
    assert_eq!(partial["fields"], before_missing_table["fields"]);
    assert_eq!(partial["raw_sources"], before_missing_table["raw_sources"]);
    assert_eq!(partial["spools"], before_missing_table["spools"]);
    assert_eq!(partial["media"]["state"], "source_table_absent");
    assert!(partial["media"]["rows"].is_null());
    assert!(partial["media"]["indexed_bytes"].is_null());
    assert_eq!(partial["inventory_complete"], false);
    assert_eq!(
        partial["missing_source_tables"],
        serde_json::json!(["conversation_media_parts"])
    );
    assert!(inventory::require_complete(&partial).is_err());
    save_checkpoint(
        &runner.checkpoint.with_extension("all.json"),
        &serde_json::json!({"verified":true}),
    )
    .unwrap();
    assert!(
        runner
            .verify_all_from(&source, "fixture", pepper)
            .await
            .is_err()
    );
    let failed: serde_json::Value = serde_json::from_reader(
        std::fs::File::open(runner.checkpoint.with_extension("all.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(failed["verified"], false);
    assert_eq!(failed["source_inventory"], partial);
    assert!(runner.require_all_verification().is_err());
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
        .execute(&administrative)
        .await
        .unwrap();
}

#[test]
fn checkpoint_identity_and_atom_key_reject_cross_scope_replay() {
    assert!(
        transfer_key(
            "fixture",
            &Cursor {
                tenant_id: "bad".into(),
                content_hash: "a".repeat(64)
            }
        )
        .is_err()
    );
    assert!(
        transfer_key(
            "fixture",
            &Cursor {
                tenant_id: Uuid::nil().to_string(),
                content_hash: "../bad".into()
            }
        )
        .is_err()
    );
}

#[tokio::test]
async fn preexisting_compressed_atom_cas_is_copied_from_the_real_source_and_verified() {
    let database_url = std::env::var("MTC_TEST_POSTGRES_URL").unwrap();
    let administrative = PgPool::connect(&database_url).await.unwrap();
    let name = format!("mtc_test_{}", Uuid::now_v7().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&administrative)
        .await
        .unwrap();
    let mut url = url::Url::parse(&database_url).unwrap();
    url.set_path(&name);
    let pool = PgPool::connect(url.as_str()).await.unwrap();
    sqlx::raw_sql("CREATE TABLE semantic_atoms(tenant_id TEXT NOT NULL, content_hash TEXT NOT NULL, content_json TEXT NOT NULL, PRIMARY KEY(tenant_id, content_hash)); CREATE TABLE context_nodes(tenant_id TEXT NOT NULL, node_hash TEXT NOT NULL, parent_hash TEXT, atom_hash TEXT NOT NULL, depth BIGINT NOT NULL, PRIMARY KEY(tenant_id,node_hash));").execute(&pool).await.unwrap();
    let tenant = Uuid::now_v7();
    let source = ArchiveStore::from_config(&Config::for_test(url.to_string()))
        .await
        .unwrap();
    let body = serde_json::json!({"role":"user", "content":"工具😀\n".repeat(100000)}).to_string();
    let hash = blake3::hash(body.as_bytes()).to_hex().to_string();
    let mut writer = source
        .start_compressed_writer("fixture/existing-atom")
        .await
        .unwrap();
    for chunk in body.as_bytes().chunks(65536) {
        writer.write(Bytes::copy_from_slice(chunk)).await.unwrap();
    }
    let staged = writer.finish_staged().await.unwrap();
    let original = source
        .promote_staged_text_to_cas(tenant, &staged)
        .await
        .unwrap();
    let reference = ConversationBodyReference {
        conversation_body_v1: original.clone(),
        chars: body.chars().count() as u64,
    };
    sqlx::query("INSERT INTO semantic_atoms VALUES ($1,$2,$3)")
        .bind(tenant.to_string())
        .bind(&hash)
        .bind(serde_json::to_string(&reference).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let node = memeloop_token_center::conversation::digest_parts(None, &hash);
    sqlx::query("INSERT INTO context_nodes VALUES ($1,$2,NULL,$3,1)")
        .bind(tenant.to_string())
        .bind(&node)
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    let mut config = Config::for_test(url.to_string());
    config.archive_backend = memeloop_token_center::config::ArchiveBackend::S3;
    config.s3_endpoint = Some(std::env::var("MTC_RUSTFS_TEST_ENDPOINT").unwrap());
    config.s3_bucket = Some(std::env::var("MTC_RUSTFS_TEST_BUCKET").unwrap());
    config.s3_access_key = Some(std::env::var("MTC_RUSTFS_TEST_ACCESS_KEY").unwrap());
    config.s3_secret_key = Some(std::env::var("MTC_RUSTFS_TEST_SECRET_KEY").unwrap());
    config.s3_region = "us-east-1".into();
    config.s3_allow_http = true;
    let directory = tempfile::tempdir().unwrap();
    let runner = Runner {
        pool: pool.clone(),
        source: Some(source.clone()),
        target: ArchiveStore::from_config(&config).await.unwrap(),
        checkpoint: directory.path().join("cas.json"),
        identity: "existing-cas-fixture".into(),
    };
    assert_eq!(runner.copy().await.unwrap().copied_rows, 1);
    assert!(runner.verify().await.unwrap().verified);
    let cursor = Cursor {
        tenant_id: tenant.to_string(),
        content_hash: hash.clone(),
    };
    let transfer = runner.transfer(&cursor).await.unwrap();
    assert_eq!(transfer.reference.chars, reference.chars);
    assert_eq!(transfer.reference.conversation_body_v1, original);
    assert_eq!(
        transfer.reference.conversation_body_v1.blake3_digest,
        original.blake3_digest
    );
    assert_eq!(
        runner
            .target
            .get_tenant_content(tenant, &transfer.reference.conversation_body_v1, body.len())
            .await
            .unwrap()
            .as_ref(),
        body.as_bytes()
    );
    source
        .verify_tenant_content(tenant, &original)
        .await
        .unwrap();
    let source_json: String = sqlx::query_scalar("SELECT content_json FROM semantic_atoms")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(source_json, serde_json::to_string(&reference).unwrap());
    let missing_source = Runner {
        pool: pool.clone(),
        source: None,
        target: runner.target.clone(),
        checkpoint: directory.path().join("no-source.json"),
        identity: "missing-source-fixture".into(),
    };
    assert!(
        missing_source.copy().await.is_err(),
        "a readable target is not proof of a source copy"
    );
    let mut tampered = reference;
    tampered.chars += 1;
    sqlx::query("UPDATE semantic_atoms SET content_json=$1")
        .bind(serde_json::to_string(&tampered).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert!(runner.verify().await.is_err());
    assert!(!runner.load_checkpoint().unwrap().verified);
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
        .execute(&administrative)
        .await
        .unwrap();
}
