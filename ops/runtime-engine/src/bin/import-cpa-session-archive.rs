use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use memeloop_token_center::{
    archive::ArchiveStore,
    db::Database,
    session_archive_import::{
        MAX_SESSION_ARCHIVE_LINE_BYTES, MAX_SESSION_ARCHIVE_PLAN_BYTES,
        SessionArchiveImportOptions, config::importer_config, import_session_archive,
        validate_session_archive_import_options,
    },
};

#[derive(Debug, Parser)]
#[command(about = "Import a lossless cpa-session-archive JSONL export")]
struct Args {
    #[arg(long, env = "CPA_SESSION_ARCHIVE_INPUT")]
    input: PathBuf,
    /// Writable, pod-local directory for the bounded sealed import plan.
    #[arg(long, env = "SESSION_ARCHIVE_PLAN_DIRECTORY", default_value = "/tmp")]
    plan_directory: PathBuf,
    #[arg(
        long,
        env = "IMPORT_TENANT_EXTERNAL_ID",
        default_value = "cpa-dogfood-import"
    )]
    tenant_external_id: String,
    #[arg(
        long,
        env = "CPAMP_IMPORT_SOURCE",
        default_value = "cpamp-usage-events-v1"
    )]
    cpamp_source: String,
    #[arg(
        long,
        env = "SESSION_ARCHIVE_IMPORT_SOURCE",
        default_value = "cpa-session-archive-v2"
    )]
    archive_source: String,
    #[arg(long, env = "SESSION_ARCHIVE_OVERLAP_MS", default_value_t = 86_400_000)]
    overlap_ms: i64,
    #[arg(
        long,
        env = "SESSION_ARCHIVE_TIME_TOLERANCE_MS",
        default_value_t = 300_000
    )]
    time_tolerance_ms: i64,
    #[arg(
        long,
        env = "SESSION_ARCHIVE_MAX_LINE_BYTES",
        default_value_t = MAX_SESSION_ARCHIVE_LINE_BYTES
    )]
    max_line_bytes: usize,
    #[arg(
        long,
        env = "SESSION_ARCHIVE_MAX_PLAN_BYTES",
        default_value_t = MAX_SESSION_ARCHIVE_PLAN_BYTES
    )]
    max_plan_bytes: u64,
    /// Count unmapped records during dry-run. Deliberately incompatible with --apply.
    #[arg(
        long,
        env = "SESSION_ARCHIVE_ALLOW_UNMAPPED",
        default_value_t = false,
        action = clap::ArgAction::Set
    )]
    allow_unmapped: bool,
    /// Admit only records whose identity is absent or unknown into the sealed
    /// operator-only quarantine. Malformed or ambiguous evidence remains fatal.
    #[arg(
        long,
        env = "SESSION_ARCHIVE_QUARANTINE_UNKNOWN_IDENTITIES",
        default_value_t = false,
        action = clap::ArgAction::Set
    )]
    quarantine_unknown_identities: bool,
    #[arg(long, env = "SESSION_ARCHIVE_TENANT_BINDING_KIND")]
    quarantine_tenant_binding_kind: Option<String>,
    #[arg(long, env = "SESSION_ARCHIVE_TENANT_BINDING_PROOF")]
    quarantine_tenant_binding_proof: Option<String>,
    #[arg(long, env = "SESSION_ARCHIVE_APPROVED_BY_SERVICE_ID")]
    quarantine_approved_by_service_id: Option<uuid::Uuid>,
    /// Perform writes. Without this flag the command is a fail-closed dry run.
    #[arg(long)]
    apply: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args).await {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error_code) => {
            eprintln!("session archive import failed: {error_code}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &Args) -> Result<String, &'static str> {
    let options = SessionArchiveImportOptions {
        input: &args.input,
        plan_directory: &args.plan_directory,
        tenant_external_id: &args.tenant_external_id,
        cpamp_source: &args.cpamp_source,
        archive_source: &args.archive_source,
        overlap_ms: args.overlap_ms,
        time_tolerance_ms: args.time_tolerance_ms,
        max_line_bytes: args.max_line_bytes,
        max_plan_bytes: args.max_plan_bytes,
        allow_unmapped: args.allow_unmapped,
        quarantine_unknown_identities: args.quarantine_unknown_identities,
        quarantine_tenant_binding_kind: args.quarantine_tenant_binding_kind.as_deref(),
        quarantine_tenant_binding_proof: args.quarantine_tenant_binding_proof.as_deref(),
        quarantine_approved_by_service_id: args.quarantine_approved_by_service_id,
        apply: args.apply,
    };
    // Reject unsafe resource settings before opening database or object-store connections.
    validate_session_archive_import_options(&options).map_err(|_| "import_options_invalid")?;
    let config = importer_config().map_err(|_| "configuration_invalid")?;
    let db = Database::connect_with_max(&config.database_url, 2)
        .await
        .map_err(|_| "database_connect_failed")?;
    db.ensure_session_archive_import_schema()
        .await
        .map_err(|_| "database_schema_invalid")?;
    let archive = ArchiveStore::from_config(&config)
        .await
        .map_err(|_| "archive_initialization_failed")?;
    let stats = import_session_archive(&db, &archive, &options)
        .await
        .map_err(|_| "archive_import_failed")?;
    serde_json::to_string(&stats).map_err(|_| "result_serialization_failed")
}
