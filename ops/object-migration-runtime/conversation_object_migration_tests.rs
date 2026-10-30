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
         CREATE TABLE request_archive_spools(request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, reservation_id TEXT NOT NULL, state TEXT NOT NULL, chunk_count BIGINT NOT NULL, byte_count BIGINT NOT NULL);
         CREATE TABLE response_archive_spools(LIKE request_archive_spools INCLUDING ALL);
         CREATE TABLE request_archive_spool_chunks(request_id TEXT NOT NULL, seq BIGINT NOT NULL, ciphertext TEXT NOT NULL, byte_count BIGINT NOT NULL, PRIMARY KEY(request_id, seq));
         CREATE TABLE response_archive_spool_chunks(LIKE request_archive_spool_chunks INCLUDING ALL);
         CREATE TABLE conversation_semantic_payloads(request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, request_json TEXT NOT NULL);
         CREATE TABLE conversation_projection_outbox(request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, request_json TEXT NOT NULL, semantic_snapshot_json TEXT, semantic_payload_snapshot_json TEXT, key_snapshot_json TEXT, hints_json TEXT NOT NULL);",
    ).execute(&pool).await.unwrap();
    let tenant = Uuid::now_v7();
    let document = serde_json::json!({"role":"tool", "content":"工具\n".repeat(200000), "tool_call_id":"call-1", "unknown":[1,2,3]}).to_string();
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
    let runner = Runner {
        pool: pool.clone(),
        target: ArchiveStore::from_config(&Config::for_test(url.to_string()))
            .await
            .unwrap(),
        checkpoint: directory.path().join("checkpoint.json"),
        identity: "fixture".into(),
    };
    let source = ArchiveStore::from_config(&Config::for_test(url.to_string()))
        .await
        .unwrap();
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
    sqlx::query("INSERT INTO session_archive_quarantine_record_versions VALUES ($1, 'retained-quarantine', $2, NULL)")
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
    assert_eq!(locators.copied_rows, 4);
    assert_eq!(
        locators.copied_bytes,
        2 * document.len() as u64 + response.len() as u64 + 15
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
    let copied = runner.copy().await.unwrap();
    let inventory = inventory::inventory(&pool).await.unwrap();
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
    let reconstructed = runner.reconstruct_dialogues(false).await.unwrap();
    assert_eq!(
        (
            reconstructed.observations,
            reconstructed.events,
            reconstructed.media
        ),
        (2, 3, 3)
    );
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
