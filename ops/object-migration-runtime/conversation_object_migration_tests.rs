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
         CREATE TABLE context_nodes(tenant_id TEXT NOT NULL, node_hash TEXT NOT NULL, parent_hash TEXT, atom_hash TEXT NOT NULL, depth BIGINT NOT NULL, PRIMARY KEY(tenant_id, node_hash));",
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
    let directory = tempfile::tempdir().unwrap();
    let runner = Runner {
        pool: pool.clone(),
        target: ArchiveStore::from_config(&Config::for_test(url.to_string()))
            .await
            .unwrap(),
        checkpoint: directory.path().join("checkpoint.json"),
        identity: "fixture".into(),
    };
    assert!(runner.cutover_test().await.is_err());
    let copied = runner.copy().await.unwrap();
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
    assert_eq!(verified.verified_context_nodes, 1);
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
