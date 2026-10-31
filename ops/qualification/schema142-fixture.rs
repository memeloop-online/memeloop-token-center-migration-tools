//! CI-only fixture creation. No migration source edits or ledger fabrication.
use memeloop_token_center::db::Database;

#[tokio::test]
async fn original_schema142_fixture() {
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    let url = std::env::var("MTC_TEST_POSTGRES_URL").unwrap();
    assert!(url.ends_with("/rehearsal142"));
    let db = Database::connect_for_migration(&url, 2).await.unwrap();
    db.migrate().await.unwrap();
    db.convert_sealed_state(&[7; 32]).await.unwrap();
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    let row: (i64, String) = sqlx::query_as(
        "SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT 1",
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(row, (142, "plaintext state instead of sealed envelopes".into()));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM schema_migrations")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 141); // Original source has no version114.
    pool.close().await;
}
