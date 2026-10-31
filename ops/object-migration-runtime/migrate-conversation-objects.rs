use std::{fs::OpenOptions, io::Write, path::PathBuf, process::ExitCode};

use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures_util::StreamExt;
use memeloop_token_center::{
    archive::{ArchiveStore, ConversationBodyReference},
    config::Config,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use uuid::Uuid;

type Failure = Box<dyn std::error::Error + Send + Sync>;
type Result<Value> = std::result::Result<Value, Failure>;

#[path = "conversation-object-modules/inventory.rs"]
mod inventory;
#[path = "conversation-object-modules/locators.rs"]
mod locators;
#[path = "conversation-object-modules/payloads.rs"]
mod payloads;
#[path = "conversation-object-modules/reconstruction.rs"]
mod reconstruction;
#[path = "conversation-object-modules/spools.rs"]
mod spools;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Phase {
    Inventory,
    Copy,
    Verify,
    CutoverTest,
    CopyLocators,
    VerifyLocators,
    CopySpools,
    VerifySpools,
    CopyPayloads,
    VerifyPayloads,
    Reconstruct,
    VerifyReconstruction,
    VerifyAll,
}

#[derive(Parser)]
#[command(about = "Checkpointed conversation object transfer; source mutation is TEST-only")]
struct Args {
    #[arg(long, value_enum, default_value = "inventory")]
    phase: Phase,
    #[arg(long)]
    checkpoint: PathBuf,
    #[arg(long)]
    writers_quiesced: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Cursor {
    tenant_id: String,
    content_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transfer {
    format_version: u32,
    identity: String,
    cursor: Cursor,
    source_md5: String,
    reference: ConversationBodyReference,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    format_version: u32,
    identity: String,
    cursor: Cursor,
    copied_rows: u64,
    copied_bytes: u64,
    ordered_digest: String,
    expected_rows: u64,
    copied: bool,
    verified_rows: u64,
    verified_context_nodes: u64,
    verified: bool,
    cutover_cursor: Cursor,
    cutover_rows: u64,
    cutover_complete: bool,
}

struct Runner {
    pool: PgPool,
    source: Option<ArchiveStore>,
    target: ArchiveStore,
    checkpoint: PathBuf,
    identity: String,
}

fn transfer_key(identity: &str, cursor: &Cursor) -> Result<String> {
    let tenant = Uuid::parse_str(&cursor.tenant_id)?;
    if cursor.content_hash.len() != 64
        || !cursor
            .content_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid content identity".into());
    }
    Ok(format!(
        "migration-receipts/conversation-v1/{identity}/atoms/{tenant}/{}.json",
        cursor.content_hash
    ))
}

fn save_checkpoint<Value: Serialize>(path: &std::path::Path, checkpoint: &Value) -> Result<()> {
    let directory = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(temporary.as_file_mut(), checkpoint)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn ordered_digest(
    previous: &str,
    cursor: &Cursor,
    reference: &ConversationBodyReference,
) -> String {
    let mut digest = blake3::Hasher::new();
    for value in [
        previous,
        &cursor.tenant_id,
        &cursor.content_hash,
        &reference.conversation_body_v1.blake3_digest,
    ] {
        digest.update(&(value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(&reference.conversation_body_v1.size_bytes.to_le_bytes());
    digest.update(&reference.chars.to_le_bytes());
    digest.finalize().to_hex().to_string()
}

// Historical TEST uses the same database name as production. Its namespace
// comes from the Pod downward API and its endpoint must name the TEST CNPG
// service explicitly; a namespace assertion alone cannot authorize writes.
fn test_source_is_explicit(database: &str, source: &str, namespace: Option<&str>) -> bool {
    let Ok(source) = url::Url::parse(source) else {
        return false;
    };
    if source.path().trim_start_matches('/') != database {
        return false;
    }
    if database.ends_with("_test") || database.starts_with("mtc_test_") {
        return true;
    }
    database == "memeloop_token_center"
        && namespace == Some("memeloop-token-center-test")
        && matches!(
            source.host_str(),
            Some(
                "memeloop-token-center-test-pg-rw"
                    | "memeloop-token-center-test-pg-rw.memeloop-token-center-test"
                    | "memeloop-token-center-test-pg-rw.memeloop-token-center-test.svc"
                    | "memeloop-token-center-test-pg-rw.memeloop-token-center-test.svc.cluster.local"
            )
        )
}

#[test]
fn test_source_guard_rejects_production_with_the_same_database_name() {
    let test = "postgres://fixture:fixture@memeloop-token-center-test-pg-rw/memeloop_token_center";
    let prod = "postgres://fixture:fixture@memeloop-token-center-pg-rw/memeloop_token_center";
    assert!(test_source_is_explicit(
        "memeloop_token_center",
        test,
        Some("memeloop-token-center-test")
    ));
    assert!(!test_source_is_explicit(
        "memeloop_token_center",
        test,
        None
    ));
    assert!(!test_source_is_explicit(
        "memeloop_token_center",
        test,
        Some("memeloop-token-center")
    ));
    assert!(!test_source_is_explicit(
        "memeloop_token_center",
        prod,
        Some("memeloop-token-center-test")
    ));
    assert!(!test_source_is_explicit(
        "wrong_database",
        test,
        Some("memeloop-token-center-test")
    ));
    assert!(test_source_is_explicit(
        "fixture_test",
        "postgres://fixture@localhost/fixture_test",
        None
    ));
}

impl Runner {
    fn load_checkpoint(&self) -> Result<Checkpoint> {
        match std::fs::File::open(&self.checkpoint) {
            Ok(file) => {
                let checkpoint: Checkpoint = serde_json::from_reader(file)?;
                if checkpoint.format_version != 1 || checkpoint.identity != self.identity {
                    return Err("checkpoint source/target identity mismatch".into());
                }
                Ok(checkpoint)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Checkpoint {
                format_version: 1,
                identity: self.identity.clone(),
                ..Default::default()
            }),
            Err(error) => Err(error.into()),
        }
    }

    async fn next_atom(&self, after: &Cursor) -> Result<Option<Cursor>> {
        let row = sqlx::query(
            "SELECT tenant_id, content_hash FROM semantic_atoms WHERE (tenant_id, content_hash) > ($1, $2) ORDER BY tenant_id, content_hash LIMIT 1",
        )
        .bind(&after.tenant_id)
        .bind(&after.content_hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(Cursor {
                tenant_id: row.try_get("tenant_id")?,
                content_hash: row.try_get("content_hash")?,
            })
        })
        .transpose()
    }

    async fn source_reference(
        &self,
        cursor: &Cursor,
        copy: bool,
    ) -> Result<(ConversationBodyReference, String)> {
        self.source_field_reference(cursor, payloads::SourceField::Atom, copy)
            .await
    }

    async fn transfer_existing_body_reference(
        &self,
        tenant: Uuid,
        reference: &ConversationBodyReference,
        copy: bool,
    ) -> Result<ConversationBodyReference> {
        let source = self
            .source
            .as_ref()
            .ok_or("existing atom CAS requires explicit source object storage configuration")?;
        let mut stream = source
            .open_tenant_content(tenant, &reference.conversation_body_v1)
            .await?
            .stream;
        let staging = format!(
            "migration-staging/conversation-v1/{}/{}",
            self.identity,
            Uuid::now_v7()
        );
        let mut writer = if copy {
            Some(self.target.start_writer(&staging).await?)
        } else {
            None
        };
        let mut digest = blake3::Hasher::new();
        let mut bytes = 0_u64;
        let mut chars = 0_u64;
        let mut pending = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .ok_or("atom body byte count overflow")?;
            digest.update(&chunk);
            for part in chunk.chunks(65536) {
                pending.extend_from_slice(part);
                let valid = match std::str::from_utf8(&pending) {
                    Ok(text) => text.len(),
                    Err(error) if error.error_len().is_none() => error.valid_up_to(),
                    Err(_) => return Err("source atom body is not UTF-8".into()),
                };
                chars = chars
                    .checked_add(std::str::from_utf8(&pending[..valid])?.chars().count() as u64)
                    .ok_or("atom character count overflow")?;
                pending.drain(..valid);
            }
            if let Some(writer) = &mut writer {
                writer.write(chunk).await?;
            }
        }
        let digest = digest.finalize().to_hex().to_string();
        if !pending.is_empty()
            || chars != reference.chars
            || bytes != reference.conversation_body_v1.size_bytes
            || digest != reference.conversation_body_v1.blake3_digest
        {
            return Err("source atom body reference count/hash/characters mismatch".into());
        }
        let object = if let Some(writer) = writer {
            let staged = writer.finish_staged().await?;
            if staged.size_bytes != bytes || staged.blake3_digest != digest {
                return Err("atom CAS transfer hash mismatch".into());
            }
            let object = self
                .target
                .promote_staged_text_to_cas(tenant, &staged)
                .await?;
            self.target.delete(&staged.object_locator).await?;
            object
        } else {
            memeloop_token_center::archive::CasArchiveObject {
                object_locator: format!("tenants/{tenant}/cas/v1/blake3/{}/{digest}", &digest[..2]),
                blake3_digest: digest,
                size_bytes: bytes,
            }
        };
        self.target.verify_tenant_content(tenant, &object).await?;
        Ok(ConversationBodyReference {
            conversation_body_v1: object,
            chars,
        })
    }

    async fn source_field_reference(
        &self,
        cursor: &Cursor,
        field: payloads::SourceField,
        copy: bool,
    ) -> Result<(ConversationBodyReference, String)> {
        let (table, id, column) = field.columns();
        let tenant = Uuid::parse_str(&cursor.tenant_id)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT CAST(length({column}) AS BIGINT) AS chars, CAST(octet_length({column}) AS BIGINT) AS bytes, md5({column}) AS digest, left({column}, 4096) AS prefix FROM {table} WHERE tenant_id = $1 AND {id} = $2"
        )))
        .bind(&cursor.tenant_id).bind(&cursor.content_hash)
        .fetch_one(&mut *transaction).await?;
        let chars = u64::try_from(row.try_get::<i64, _>("chars")?)?;
        let expected_bytes = u64::try_from(row.try_get::<i64, _>("bytes")?)?;
        let source_md5: String = row.try_get("digest")?;
        let prefix: String = row.try_get("prefix")?;
        if field == payloads::SourceField::Atom
            && expected_bytes <= 4096
            && let Ok(reference) = serde_json::from_str::<ConversationBodyReference>(&prefix)
        {
            transaction.commit().await?;
            let reference = self
                .transfer_existing_body_reference(tenant, &reference, copy)
                .await?;
            return Ok((reference, source_md5));
        }
        let staging = format!(
            "migration-staging/conversation-v1/{}/{}",
            self.identity,
            Uuid::now_v7()
        );
        let mut writer = if copy {
            Some(self.target.start_writer(&staging).await?)
        } else {
            None
        };
        let mut digest = blake3::Hasher::new();
        let mut offset = 0_u64;
        let mut bytes = 0_u64;
        while offset < chars {
            let chunk: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT substring({column} FROM $3 FOR 65536) FROM {table} WHERE tenant_id = $1 AND {id} = $2"
            )))
            .bind(&cursor.tenant_id).bind(&cursor.content_hash)
            .bind(i32::try_from(offset.checked_add(1).ok_or("character offset overflow")?)?)
            .fetch_one(&mut *transaction).await?;
            if chunk.is_empty() {
                return Err("source ended before its declared character count".into());
            }
            offset += chunk.chars().count() as u64;
            bytes += chunk.len() as u64;
            digest.update(chunk.as_bytes());
            if let Some(writer) = &mut writer {
                writer.write(Bytes::from(chunk)).await?;
            }
        }
        transaction.commit().await?;
        if bytes != expected_bytes || offset != chars {
            return Err("source byte/character count mismatch".into());
        }
        let blake3_digest = digest.finalize().to_hex().to_string();
        let object = if let Some(writer) = writer {
            let staged = writer.finish_staged().await?;
            if staged.blake3_digest != blake3_digest || staged.size_bytes != expected_bytes {
                return Err("streamed transfer digest mismatch".into());
            }
            let object = self
                .target
                .promote_staged_text_to_cas(tenant, &staged)
                .await?;
            self.target.delete(&staged.object_locator).await?;
            object
        } else {
            memeloop_token_center::archive::CasArchiveObject {
                object_locator: format!(
                    "tenants/{tenant}/cas/v1/blake3/{}/{blake3_digest}",
                    &blake3_digest[..2]
                ),
                blake3_digest,
                size_bytes: expected_bytes,
            }
        };
        Ok((
            ConversationBodyReference {
                conversation_body_v1: object,
                chars,
            },
            source_md5,
        ))
    }

    async fn transfer(&self, cursor: &Cursor) -> Result<Transfer> {
        let bytes = self
            .target
            .get_bounded(&transfer_key(&self.identity, cursor)?, 16384)
            .await?;
        let transfer: Transfer = serde_json::from_slice(&bytes)?;
        if transfer.format_version != 1
            || transfer.identity != self.identity
            || transfer.cursor != *cursor
        {
            return Err("transfer receipt identity mismatch".into());
        }
        Ok(transfer)
    }

    async fn copy(&self) -> Result<Checkpoint> {
        let mut checkpoint = self.load_checkpoint()?;
        if checkpoint.copied {
            return Ok(checkpoint);
        }
        if checkpoint.copied_rows == 0 {
            checkpoint.expected_rows = u64::try_from(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM semantic_atoms")
                    .fetch_one(&self.pool)
                    .await?,
            )?;
            save_checkpoint(&self.checkpoint, &checkpoint)?;
        }
        while let Some(cursor) = self.next_atom(&checkpoint.cursor).await? {
            let (reference, source_md5) = self.source_reference(&cursor, true).await?;
            let transfer = Transfer {
                format_version: 1,
                identity: self.identity.clone(),
                cursor: cursor.clone(),
                source_md5,
                reference,
            };
            let key = transfer_key(&self.identity, &cursor)?;
            self.target
                .put(&key, Bytes::from(serde_json::to_vec(&transfer)?))
                .await?;
            let checked = self.transfer(&cursor).await?;
            if serde_json::to_vec(&checked)? != serde_json::to_vec(&transfer)? {
                return Err("transfer receipt readback mismatch".into());
            }
            checkpoint.copied_rows += 1;
            checkpoint.copied_bytes += transfer.reference.conversation_body_v1.size_bytes;
            checkpoint.ordered_digest =
                ordered_digest(&checkpoint.ordered_digest, &cursor, &transfer.reference);
            checkpoint.cursor = cursor;
            save_checkpoint(&self.checkpoint, &checkpoint)?;
        }
        if checkpoint.copied_rows != checkpoint.expected_rows {
            return Err(
                "source count changed; quiesce writers before restarting the inventory".into(),
            );
        }
        checkpoint.copied = true;
        save_checkpoint(&self.checkpoint, &checkpoint)?;
        Ok(checkpoint)
    }

    async fn verify(&self) -> Result<Checkpoint> {
        let mut checkpoint = self.load_checkpoint()?;
        if !checkpoint.copied || checkpoint.cutover_rows != 0 {
            return Err("verify requires a completed copy before cutover".into());
        }
        checkpoint.verified = false;
        checkpoint.verified_rows = 0;
        save_checkpoint(&self.checkpoint, &checkpoint)?;
        let mut cursor = Cursor::default();
        let mut count = 0_u64;
        let mut bytes = 0_u64;
        let mut digest = String::new();
        while let Some(next) = self.next_atom(&cursor).await? {
            let transfer = self.transfer(&next).await?;
            let (source, source_md5) = self.source_reference(&next, false).await?;
            if source_md5 != transfer.source_md5
                || serde_json::to_vec(&source)? != serde_json::to_vec(&transfer.reference)?
            {
                return Err("source differs from copied transfer".into());
            }
            self.target
                .verify_tenant_content(
                    Uuid::parse_str(&next.tenant_id)?,
                    &source.conversation_body_v1,
                )
                .await?;
            digest = ordered_digest(&digest, &next, &source);
            count += 1;
            bytes += source.conversation_body_v1.size_bytes;
            cursor = next;
        }
        if count != checkpoint.expected_rows
            || bytes != checkpoint.copied_bytes
            || digest != checkpoint.ordered_digest
        {
            return Err("full-copy count, byte or ordered hash mismatch".into());
        }
        checkpoint.verified_context_nodes = self.verify_context_nodes().await?;
        checkpoint.verified_rows = count;
        checkpoint.verified = true;
        save_checkpoint(&self.checkpoint, &checkpoint)?;
        Ok(checkpoint)
    }

    async fn verify_context_nodes(&self) -> Result<u64> {
        let mut tenant = String::new();
        let mut node = String::new();
        let mut count = 0_u64;
        loop {
            let row = sqlx::query(
                "SELECT n.tenant_id, n.node_hash, n.parent_hash, n.atom_hash, n.depth, p.depth AS parent_depth FROM context_nodes n LEFT JOIN context_nodes p ON p.tenant_id = n.tenant_id AND p.node_hash = n.parent_hash WHERE (n.tenant_id, n.node_hash) > ($1, $2) ORDER BY n.tenant_id, n.node_hash LIMIT 1",
            )
            .bind(&tenant).bind(&node).fetch_optional(&self.pool).await?;
            let Some(row) = row else { break };
            tenant = row.try_get("tenant_id")?;
            node = row.try_get("node_hash")?;
            let parent: Option<String> = row.try_get("parent_hash")?;
            let atom: String = row.try_get("atom_hash")?;
            let depth: i64 = row.try_get("depth")?;
            let parent_depth: Option<i64> = row.try_get("parent_depth")?;
            if depth <= 0
                || memeloop_token_center::conversation::digest_parts(parent.as_deref(), &atom)
                    != node
                || if parent.is_some() {
                    parent_depth.and_then(|depth| depth.checked_add(1)) != Some(depth)
                } else {
                    depth != 1
                }
            {
                return Err("conversation parent/order/hash reconstruction failed".into());
            }
            let transfer = self
                .transfer(&Cursor {
                    tenant_id: tenant.clone(),
                    content_hash: atom,
                })
                .await?;
            self.target
                .verify_tenant_content(
                    Uuid::parse_str(&tenant)?,
                    &transfer.reference.conversation_body_v1,
                )
                .await?;
            count += 1;
        }
        Ok(count)
    }

    fn verification_inputs(&self) -> Result<serde_json::Value> {
        let atoms = self.load_checkpoint()?;
        let mut inputs = serde_json::json!({
            "atoms": {"verified": atoms.verified, "rows": atoms.expected_rows,
                "bytes": atoms.copied_bytes, "digest": atoms.ordered_digest},
        });
        for extension in [
            "locators.json",
            "spools.json",
            "payloads.json",
            "reconstruction.json",
        ] {
            let bytes = std::fs::read(self.checkpoint.with_extension(extension))?;
            inputs[extension] = serde_json::json!(blake3::hash(&bytes).to_hex().to_string());
        }
        Ok(inputs)
    }

    fn require_all_verification(&self) -> Result<()> {
        let receipt: serde_json::Value = serde_json::from_reader(std::fs::File::open(
            self.checkpoint.with_extension("all.json"),
        )?)?;
        if receipt["format_version"] != 1
            || receipt["identity"] != self.identity
            || receipt["verified"] != true
            || receipt["inputs"] != self.verification_inputs()?
        {
            return Err("fresh all-source verification receipt required".into());
        }
        Ok(())
    }

    async fn verify_all_from(
        &self,
        source: &ArchiveStore,
        source_identity: &str,
        pepper: &[u8],
    ) -> Result<serde_json::Value> {
        let path = self.checkpoint.with_extension("all.json");
        let mut receipt = serde_json::json!({
            "format_version":1, "identity":self.identity, "verified":false,
            "complete_training_fidelity_certified":false,
        });
        // Invalidate the aggregate before any I/O. A failed rerun must never
        // leave an older green receipt authorizing source mutation.
        save_checkpoint(&path, &receipt)?;
        let before = inventory::inventory(&self.pool).await?;
        receipt["atoms"] = serde_json::to_value(self.verify().await?)?;
        receipt["locators"] = serde_json::to_value(
            self.transfer_locators_from(source, source_identity, true)
                .await?,
        )?;
        receipt["spools"] = serde_json::to_value(self.transfer_spools(pepper, true).await?)?;
        receipt["payloads"] = serde_json::to_value(self.transfer_payloads(true).await?)?;
        receipt["reconstruction"] = serde_json::to_value(self.reconstruct_dialogues(true).await?)?;
        let after = inventory::inventory(&self.pool).await?;
        if before != after {
            return Err("source inventory changed during all-source verification".into());
        }
        receipt["source_inventory"] = after;
        receipt["inputs"] = self.verification_inputs()?;
        receipt["verified"] = serde_json::json!(true);
        save_checkpoint(&path, &receipt)?;
        Ok(receipt)
    }

    async fn cutover_test(&self) -> Result<Checkpoint> {
        let database: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&self.pool)
            .await?;
        if !(database.ends_with("_test") || database.starts_with("mtc_test_"))
            && !test_source_is_explicit(
                &database,
                &std::env::var("MTC_DATABASE_URL").unwrap_or_default(),
                std::env::var("MTC_OBJECT_MIGRATION_TEST_NAMESPACE")
                    .ok()
                    .as_deref(),
            )
        {
            return Err(
                "source mutation is restricted to an explicitly named TEST database".into(),
            );
        }
        let mut checkpoint = self.load_checkpoint()?;
        if !checkpoint.verified || checkpoint.verified_rows != checkpoint.expected_rows {
            return Err("cutover requires full count/hash/context verification".into());
        }
        self.require_reconstruction_receipt()?;
        self.require_all_verification()?;
        if checkpoint.cutover_rows == 0 {
            self.verify().await?;
            self.reconstruct_dialogues(true).await?;
        }
        while let Some(cursor) = self.next_atom(&checkpoint.cutover_cursor).await? {
            let transfer = self.transfer(&cursor).await?;
            self.target
                .verify_tenant_content(
                    Uuid::parse_str(&cursor.tenant_id)?,
                    &transfer.reference.conversation_body_v1,
                )
                .await?;
            let encoded = serde_json::to_string(&transfer.reference)?;
            let changed = sqlx::query(
                "UPDATE semantic_atoms SET content_json = $3 WHERE tenant_id = $1 AND content_hash = $2 AND (md5(content_json) = $4 OR content_json = $3)",
            )
            .bind(&cursor.tenant_id).bind(&cursor.content_hash).bind(encoded).bind(&transfer.source_md5)
            .execute(&self.pool).await?;
            if changed.rows_affected() != 1 {
                return Err("source changed after verification; source retained".into());
            }
            checkpoint.cutover_rows += 1;
            checkpoint.cutover_cursor = cursor;
            save_checkpoint(&self.checkpoint, &checkpoint)?;
        }
        if checkpoint.cutover_rows != checkpoint.expected_rows {
            return Err("cutover count mismatch".into());
        }
        checkpoint.cutover_complete = true;
        save_checkpoint(&self.checkpoint, &checkpoint)?;
        Ok(checkpoint)
    }
}

async fn run(args: Args) -> Result<()> {
    if args.phase != Phase::Inventory && !args.writers_quiesced {
        return Err("copy/verify/cutover require --writers-quiesced; no concurrent legacy writer is supported".into());
    }
    let config = Config::from_env()?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&config.database_url)
        .await?;
    if args.phase == Phase::Inventory {
        println!("{}", inventory::inventory(&pool).await?);
        return Ok(());
    }
    let mut source = url::Url::parse(&config.database_url)?;
    source
        .set_password(None)
        .map_err(|_| "invalid database URL")?;
    source
        .set_username("")
        .map_err(|_| "invalid database URL")?;
    let target_identity = serde_json::to_vec(&(
        &config.archive_backend,
        &config.archive_path,
        &config.s3_endpoint,
        &config.s3_bucket,
    ))?;
    let identity = blake3::hash(&[source.as_str().as_bytes(), &target_identity].concat())
        .to_hex()
        .to_string();
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(args.checkpoint.with_extension("lock"))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
    let mut advisory = pool.acquire().await?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(70720261029)")
        .fetch_one(&mut *advisory)
        .await?;
    if !acquired {
        return Err("another conversation migration holds the source lock".into());
    }
    let object_source = if std::env::var_os("MTC_SOURCE_S3_ENDPOINT").is_some() {
        Some(ArchiveStore::from_config(&locators::source_config(&config)?).await?)
    } else {
        None
    };
    let runner = Runner {
        pool: pool.clone(),
        source: object_source,
        target: ArchiveStore::from_config(&config).await?,
        checkpoint: args.checkpoint,
        identity,
    };
    if args.phase == Phase::VerifyAll {
        let source_config = locators::source_config(&config)?;
        let source_identity = blake3::hash(&serde_json::to_vec(&(
            &runner.identity,
            &source_config.s3_endpoint,
            &source_config.s3_bucket,
        ))?)
        .to_hex()
        .to_string();
        let source = ArchiveStore::from_config(&source_config).await?;
        let result = runner
            .verify_all_from(&source, &source_identity, config.key_pepper.as_bytes())
            .await;
        sqlx::query("SELECT pg_advisory_unlock(70720261029)")
            .execute(&mut *advisory)
            .await?;
        println!("{}", serde_json::to_string(&result?)?);
        return Ok(());
    }
    if matches!(args.phase, Phase::Reconstruct | Phase::VerifyReconstruction) {
        let result = runner
            .reconstruct_dialogues(args.phase == Phase::VerifyReconstruction)
            .await;
        sqlx::query("SELECT pg_advisory_unlock(70720261029)")
            .execute(&mut *advisory)
            .await?;
        println!("{}", serde_json::to_string(&result?)?);
        return Ok(());
    }
    if matches!(args.phase, Phase::CopyPayloads | Phase::VerifyPayloads) {
        let result = runner
            .transfer_payloads(args.phase == Phase::VerifyPayloads)
            .await;
        sqlx::query("SELECT pg_advisory_unlock(70720261029)")
            .execute(&mut *advisory)
            .await?;
        println!("{}", serde_json::to_string(&result?)?);
        return Ok(());
    }
    if matches!(args.phase, Phase::CopySpools | Phase::VerifySpools) {
        let result = runner
            .transfer_spools(
                config.key_pepper.as_bytes(),
                args.phase == Phase::VerifySpools,
            )
            .await;
        sqlx::query("SELECT pg_advisory_unlock(70720261029)")
            .execute(&mut *advisory)
            .await?;
        println!("{}", serde_json::to_string(&result?)?);
        return Ok(());
    }
    if matches!(args.phase, Phase::CopyLocators | Phase::VerifyLocators) {
        let result = runner
            .transfer_locators(&config, args.phase == Phase::VerifyLocators)
            .await;
        sqlx::query("SELECT pg_advisory_unlock(70720261029)")
            .execute(&mut *advisory)
            .await?;
        println!("{}", serde_json::to_string(&result?)?);
        return Ok(());
    }
    let result = match args.phase {
        Phase::Copy => runner.copy().await,
        Phase::Verify => runner.verify().await,
        Phase::CutoverTest => runner.cutover_test().await,
        Phase::Inventory => unreachable!(),
        Phase::CopyLocators
        | Phase::VerifyLocators
        | Phase::CopySpools
        | Phase::VerifySpools
        | Phase::CopyPayloads
        | Phase::VerifyPayloads
        | Phase::Reconstruct
        | Phase::VerifyReconstruction
        | Phase::VerifyAll => {
            unreachable!()
        }
    };
    sqlx::query("SELECT pg_advisory_unlock(70720261029)")
        .execute(&mut *advisory)
        .await?;
    println!("{}", serde_json::to_string(&result?)?);
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!(
                "conversation object migration stopped; source or checkpoint is not verified"
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "conversation_object_migration_tests.rs"]
mod tests;
