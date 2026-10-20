use crate::config::{ArchiveBackend, Config};

pub fn importer_config() -> Result<Config, &'static str> {
    let database_url = std::env::var("MTC_DATABASE_URL").map_err(|_| "database URL required")?;
    if database_url.is_empty() {
        return Err("database URL required");
    }
    let archive_backend = match std::env::var("MTC_ARCHIVE_BACKEND")
        .as_deref()
        .unwrap_or("s3")
    {
        "s3" => ArchiveBackend::S3,
        "filesystem" => ArchiveBackend::Filesystem,
        _ => return Err("persistent archive backend required"),
    };
    let s3_allow_http = match std::env::var("MTC_S3_ALLOW_HTTP")
        .as_deref()
        .unwrap_or("false")
    {
        "true" => true,
        "false" => false,
        _ => return Err("invalid archive transport setting"),
    };
    Ok(Config {
        database_url,
        database_max_connections: 2,
        run_migrations_on_start: false,
        key_pepper: "unused-by-session-archive-importer".to_owned(),
        service_token: "unused-by-session-archive-importer".to_owned(),
        memeloop_cloud_webhook_secret: None,
        archive_backend,
        archive_object_compression_enabled: true,
        archive_path: std::env::var("MTC_ARCHIVE_PATH").ok(),
        s3_bucket: std::env::var("MTC_S3_BUCKET").ok(),
        s3_endpoint: std::env::var("MTC_S3_ENDPOINT").ok(),
        s3_region: std::env::var("MTC_S3_REGION").unwrap_or_else(|_| "us-east-1".to_owned()),
        s3_access_key: std::env::var("MTC_S3_ACCESS_KEY").ok(),
        s3_secret_key: std::env::var("MTC_S3_SECRET_KEY").ok(),
        s3_allow_http,
        allow_oauth_loopback: false,
        codex_test_loopback: false,
        ..Config::for_test(String::new())
    })
}
