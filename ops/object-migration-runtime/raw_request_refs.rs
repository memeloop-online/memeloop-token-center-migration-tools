//! Conditional relocation of one completed request's authoritative raw root.
//! This changes pointers only: no source object removal or GC authorization.
use super::*;
use memeloop_token_center::archive::CasArchiveObject;
use object_store::{
    ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion, path::Path,
};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRequestPlan {
    tenant_id: Uuid,
    request_id: Uuid,
    target_locator: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum RawPlanInput {
    Single(RawRequestPlan),
    Batch(RawBatchPlan),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawBatchPlan {
    requests: Vec<RawRequestPlan>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBatchProgress {
    identity: String,
    next: usize,
    reference_bytes: u64,
    source_streamed: u64,
    target_reused: u64,
    targets: std::collections::BTreeMap<String, u64>,
}

fn validate_batch(plan: &RawBatchPlan) -> Result<()> {
    if plan.requests.is_empty() {
        return Err("raw batch must contain requests".into());
    }
    let mut seen = std::collections::HashSet::new();
    for request in &plan.requests {
        if !seen.insert((request.tenant_id, request.request_id)) {
            return Err("duplicate raw batch request identity".into());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestVersion {
    tenant_id: String,
    request_id: String,
    key_id: String,
    reservation_id: String,
    created_at: i64,
    completed_at: i64,
    request_object: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProof {
    format_version: u32,
    identity: String,
    training_identity: String,
    source_store_identity: String,
    source: RequestVersion,
    root_bytes: Vec<u8>,
    root_etag: Option<String>,
    root_version: Option<String>,
    target: CasArchiveObject,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAudit {
    proof: RawProof,
    status: String,
}

#[derive(Clone, Copy)]
enum RawAction {
    Verify,
    Apply,
    CopyTarget,
}

async fn row<'e, E: sqlx::Executor<'e, Database = sqlx::Postgres>>(
    executor: E,
    plan: &RawRequestPlan,
    lock: bool,
) -> Result<Option<RequestVersion>> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let sql = format!(
        "SELECT tenant_id,id,key_id,reservation_id,created_at,completed_at,request_object FROM request_records WHERE tenant_id=$1 AND id=$2 AND completed_at IS NOT NULL{suffix}"
    );
    let r = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(plan.tenant_id.to_string())
        .bind(plan.request_id.to_string())
        .fetch_optional(executor)
        .await?;
    r.map(|r| {
        Ok(RequestVersion {
            tenant_id: r.try_get("tenant_id")?,
            request_id: r.try_get("id")?,
            key_id: r.try_get("key_id")?,
            reservation_id: r.try_get("reservation_id")?,
            created_at: r.try_get("created_at")?,
            completed_at: r.try_get("completed_at")?,
            request_object: r.try_get("request_object")?,
        })
    })
    .transpose()
}
fn client(config: &Config) -> Result<Arc<dyn ObjectStore>> {
    Ok(Arc::new(
        object_store::aws::AmazonS3Builder::new()
            .with_endpoint(config.s3_endpoint.as_ref().ok_or("S3 endpoint required")?)
            .with_bucket_name(config.s3_bucket.as_ref().ok_or("S3 bucket required")?)
            .with_region(&config.s3_region)
            .with_access_key_id(
                config
                    .s3_access_key
                    .as_ref()
                    .ok_or("S3 credential reference required")?,
            )
            .with_secret_access_key(
                config
                    .s3_secret_key
                    .as_ref()
                    .ok_or("S3 credential reference required")?,
            )
            .with_allow_http(config.s3_allow_http)
            .build()?,
    ))
}
async fn root(
    store: &dyn ObjectStore,
    path: &Path,
) -> Result<(Bytes, Option<String>, Option<String>)> {
    // Get body and conditional version from the same response, never HEAD+GET.
    let result = store
        .get(path)
        .await
        .map_err(|e| at_stage("raw_root_read", e))?;
    if result.meta.size > 4096 {
        return Err("raw root exceeds its metadata format".into());
    }
    let etag = result.meta.e_tag.clone();
    let version = result.meta.version.clone();
    Ok((result.bytes().await?, etag, version))
}
fn matches_committed(current: &RequestVersion, proof: &RawProof) -> bool {
    let mut committed = proof.source.clone();
    committed.request_object = proof.target.object_locator.clone();
    *current == committed
}
fn report(audit: &RawAudit) -> serde_json::Value {
    serde_json::json!({"mode":"raw_request_reference","request_id":audit.proof.source.request_id,"status":audit.status,"body_bytes":audit.proof.target.size_bytes,"source_deleted":false,"gc_authorized":false,"global_verified":false})
}

impl Runner {
    pub(super) async fn raw_plan_input(
        &self,
        config: &Config,
        input: RawPlanInput,
        copy: bool,
        apply: bool,
    ) -> Result<serde_json::Value> {
        let RawPlanInput::Batch(plan) = input else {
            let RawPlanInput::Single(plan) = input else {
                unreachable!()
            };
            return if copy {
                self.copy_raw_request_target(config, plan).await
            } else {
                self.relocate_raw_request(config, plan, apply).await
            };
        };
        let source_config = locators::source_config(config)?;
        self.raw_batch_with_clients(
            config,
            &source_config,
            plan,
            copy,
            apply,
            client(&source_config)?,
            client(config)?,
        )
        .await
    }

    async fn raw_batch_with_clients(
        &self,
        config: &Config,
        source_config: &Config,
        plan: RawBatchPlan,
        copy: bool,
        apply: bool,
        source_client: Arc<dyn ObjectStore>,
        target_client: Arc<dyn ObjectStore>,
    ) -> Result<serde_json::Value> {
        validate_batch(&plan)?;
        if !copy && !apply {
            return Err(
                "raw batch requires copy-target or explicit apply; dry-run remains single-plan"
                    .into(),
            );
        }
        let mode = if copy { "copy" } else { "apply" };
        let identity = blake3::hash(&serde_json::to_vec(&(
            "raw-request-batch-v1",
            &self.identity,
            (
                &source_config.s3_endpoint,
                &source_config.s3_bucket,
                &source_config.s3_region,
            ),
            (&config.s3_endpoint, &config.s3_bucket, &config.s3_region),
            mode,
            &plan,
        ))?)
        .to_hex()
        .to_string();
        let progress_path = self
            .checkpoint
            .with_extension(format!("raw-batch-{mode}.json"));
        let mut progress = if progress_path.exists() {
            let value: RawBatchProgress =
                serde_json::from_reader(std::fs::File::open(&progress_path)?)?;
            if value.identity != identity || value.next > plan.requests.len() {
                return Err("raw batch checkpoint plan/identity mismatch".into());
            }
            value
        } else {
            RawBatchProgress {
                identity,
                next: 0,
                reference_bytes: 0,
                source_streamed: 0,
                target_reused: 0,
                targets: std::collections::BTreeMap::new(),
            }
        };
        // Copy/apply share the per-request durable audit. Their aggregate cursors are separate.
        // Pool and archive clients are cloned handles, never additional pools or writers.
        let directory = self.checkpoint.with_extension("raw-batch-requests");
        std::fs::create_dir_all(&directory)?;
        for request in plan.requests.iter().skip(progress.next) {
            let child = Runner {
                pool: self.pool.clone(),
                source: self.source.clone(),
                target: self.target.clone(),
                checkpoint: directory
                    .join(format!("{}-{}.json", request.tenant_id, request.request_id)),
                identity: self.identity.clone(),
            };
            let result = Box::pin(child.relocate_raw_request_with_clients(
                config,
                source_config,
                request.clone(),
                if copy {
                    RawAction::CopyTarget
                } else {
                    RawAction::Apply
                },
                source_client.clone(),
                target_client.clone(),
            ))
            .await?;
            let bytes = result["body_bytes"]
                .as_u64()
                .ok_or("raw result missing byte count")?;
            if let Some(previous) = progress
                .targets
                .insert(request.target_locator.clone(), bytes)
            {
                if previous != bytes {
                    return Err("same raw target has conflicting lengths".into());
                }
            }
            progress.reference_bytes = progress
                .reference_bytes
                .checked_add(
                    result["body_bytes"]
                        .as_u64()
                        .ok_or("raw result missing byte count")?,
                )
                .ok_or("raw batch byte counter overflow")?;
            progress.source_streamed +=
                u64::from(result["source_streamed"].as_bool() == Some(true));
            progress.target_reused += u64::from(result["target_reused"].as_bool() == Some(true));
            progress.next += 1;
            save_checkpoint(&progress_path, &progress)?;
        }
        Ok(
            serde_json::json!({"mode":format!("raw_batch_{mode}"), "requests":plan.requests.len(),
            "completed":progress.next,"reference_bytes":progress.reference_bytes,
            "unique_target_objects":progress.targets.len(),
            "unique_target_bytes":progress.targets.values().sum::<u64>(),
            "reused_target_references":progress.next-progress.targets.len(),
            "source_streamed_requests":progress.source_streamed,"target_reused_requests":progress.target_reused,
            "target_cas_creation_measured":false,"source_deleted":false,"gc_authorized":false,
            "global_verified":false}),
        )
    }

    async fn copy_one_raw_target(
        &self,
        tenant: Uuid,
        original: &CasArchiveObject,
        expected: &CasArchiveObject,
    ) -> Result<()> {
        let source = self
            .source
            .as_ref()
            .ok_or("raw copy requires explicit source archive")?;
        let mut stream = source
            .open_tenant_content(tenant, original)
            .await
            .map_err(|e| at_stage("raw_source_stream", e))?
            .stream;
        let staging = format!(
            "migration-staging/raw-request-v1/{}/{}",
            self.identity,
            Uuid::now_v7()
        );
        let mut writer = if expected.object_locator.ends_with(".mtcz1") {
            self.target.start_compressed_writer(&staging).await?
        } else {
            self.target.start_writer(&staging).await?
        };
        while let Some(chunk) = stream.next().await {
            writer
                .write(chunk.map_err(|e| at_stage("raw_source_stream", e))?)
                .await
                .map_err(|e| at_stage("raw_target_write", e))?;
        }
        let staged = writer
            .finish_staged()
            .await
            .map_err(|e| at_stage("raw_target_finish", e))?;
        if staged.blake3_digest != expected.blake3_digest
            || staged.size_bytes != expected.size_bytes
        {
            return Err("raw source stream digest/length mismatch".into());
        }
        let actual = self
            .target
            .promote_staged_text_to_cas(tenant, &staged)
            .await
            .map_err(|e| at_stage("raw_target_promote", e))?;
        if actual != *expected {
            return Err("raw target CAS identity mismatch".into());
        }
        self.target.delete(&staged.object_locator).await?;
        Ok(())
    }

    pub(super) fn relocate_raw_request<'a>(
        &'a self,
        config: &'a Config,
        plan: RawRequestPlan,
        apply: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + 'a>>
    {
        self.raw_request_action(
            config,
            plan,
            if apply {
                RawAction::Apply
            } else {
                RawAction::Verify
            },
        )
    }

    pub(super) fn copy_raw_request_target<'a>(
        &'a self,
        config: &'a Config,
        plan: RawRequestPlan,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + 'a>>
    {
        self.raw_request_action(config, plan, RawAction::CopyTarget)
    }

    fn raw_request_action<'a>(
        &'a self,
        config: &'a Config,
        plan: RawRequestPlan,
        action: RawAction,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + 'a>>
    {
        Box::pin(async move {
            let source_config = locators::source_config(config)?;
            let source_client = client(&source_config)?;
            let target_client = client(config)?;
            self.relocate_raw_request_with_clients(
                config,
                &source_config,
                plan,
                action,
                source_client,
                target_client,
            )
            .await
        })
    }
    async fn relocate_raw_request_with_clients(
        &self,
        config: &Config,
        source_config: &Config,
        plan: RawRequestPlan,
        action: RawAction,
        source_client: Arc<dyn ObjectStore>,
        target_client: Arc<dyn ObjectStore>,
    ) -> Result<serde_json::Value> {
        if config.archive_backend != memeloop_token_center::config::ArchiveBackend::S3 {
            return Err("raw references require the configured S3 target".into());
        }
        if source_config.s3_endpoint == config.s3_endpoint
            && source_config.s3_bucket == config.s3_bucket
        {
            return Err("raw relocation requires distinct source and target stores".into());
        }
        let training = blake3::hash(&serde_json::to_vec(&(
            "mtc-training-s3-v1",
            &config
                .s3_endpoint
                .as_ref()
                .ok_or("target endpoint required")?,
            &config.s3_bucket.as_ref().ok_or("target bucket required")?,
            &config.s3_region,
        ))?)
        .to_hex()
        .to_string();
        let prefix = format!("stores/training/{training}/");
        let target_key = plan
            .target_locator
            .strip_prefix(&prefix)
            .ok_or("qualified target backend identity mismatch")?;
        let source_identity = blake3::hash(&serde_json::to_vec(&(
            "mtc-legacy-s3-v1",
            &source_config.s3_endpoint,
            &source_config.s3_bucket,
            &source_config.s3_region,
        ))?)
        .to_hex()
        .to_string();
        let root_path = Path::from(format!(
            "tenants/{}/raw/v1/{}/request.json",
            plan.tenant_id, plan.request_id
        ));
        let audit_path = self.checkpoint.with_extension("raw-request-audit.json");
        let stored = match std::fs::File::open(&audit_path) {
            Ok(f) => Some(serde_json::from_reader::<_, RawAudit>(f)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let mut audit = if let Some(audit) = stored {
            if audit.proof.format_version != 1
                || audit.proof.identity != self.identity
                || audit.proof.training_identity != training
                || audit.proof.source_store_identity != source_identity
                || audit.proof.source.tenant_id != plan.tenant_id.to_string()
                || audit.proof.source.request_id != plan.request_id.to_string()
                || audit.proof.target.object_locator != plan.target_locator
            {
                return Err("raw checkpoint plan/identity mismatch".into());
            }
            audit
        } else {
            let source = row(&self.pool, &plan, false)
                .await?
                .ok_or("completed source request required")?;
            let (encoded, etag, version) = root(source_client.as_ref(), &root_path).await?;
            if etag.is_none() && version.is_none() {
                return Err("conditional raw root version required".into());
            }
            let original: CasArchiveObject = serde_json::from_slice(&encoded)?;
            if original.object_locator != source.request_object
                || !original
                    .object_locator
                    .starts_with(&format!("tenants/{}/cas/v1/blake3/", plan.tenant_id))
            {
                return Err("source SQL/root do not identify one legacy CAS body".into());
            }
            let mut target = original.clone();
            target.object_locator = plan.target_locator.clone();
            RawAudit {
                proof: RawProof {
                    format_version: 1,
                    identity: self.identity.clone(),
                    training_identity: training,
                    source_store_identity: source_identity,
                    source,
                    root_bytes: encoded.to_vec(),
                    root_etag: etag,
                    root_version: version,
                    target,
                },
                status: "prepared".into(),
            }
        };
        let original: CasArchiveObject = serde_json::from_slice(&audit.proof.root_bytes)?;
        let digest = &original.blake3_digest;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid original raw digest".into());
        }
        let canonical = format!(
            "tenants/{}/cas/v1/blake3/{}/{}",
            plan.tenant_id,
            &digest[..2],
            digest
        );
        if (original.object_locator != canonical
            && original.object_locator != format!("{canonical}.mtcz1"))
            || original.object_locator != audit.proof.source.request_object
            || original.blake3_digest != audit.proof.target.blake3_digest
            || original.size_bytes != audit.proof.target.size_bytes
        {
            return Err("raw proof does not preserve the original logical body".into());
        }
        // Resolve the same raw identity; semantic payload references are never
        // evidence for the original request byte stream.
        let mut bare = audit.proof.target.clone();
        bare.object_locator = target_key.to_owned();
        if bare.object_locator != canonical && bare.object_locator != format!("{canonical}.mtcz1") {
            return Err("raw target must preserve the canonical tenant/digest key".into());
        }
        let copy_target = matches!(action, RawAction::CopyTarget);
        let mut uploaded = false;
        if copy_target {
            match target_client.head(&Path::from(target_key)).await {
                Ok(_) => {}
                Err(object_store::Error::NotFound { .. }) => {
                    self.copy_one_raw_target(plan.tenant_id, &original, &bare)
                        .await?;
                    uploaded = true;
                }
                Err(error) => return Err(at_stage("raw_target_head", error)),
            }
        }
        // New CAS promotion already performs complete target readback. An
        // existing target is streamed and verified, never trusted from HEAD.
        if !uploaded {
            self.target
                .verify_tenant_content(plan.tenant_id, &bare)
                .await
                .map_err(|e| at_stage("raw_target_readback", e))?;
        }
        if !matches!(action, RawAction::Apply) {
            let (observed, etag, version) = root(source_client.as_ref(), &root_path).await?;
            let new_root = serde_json::to_vec(&audit.proof.target)?;
            let root_matches = observed.as_ref() == new_root
                || (observed.as_ref() == audit.proof.root_bytes
                    && etag == audit.proof.root_etag
                    && version == audit.proof.root_version);
            let source_matches = row(&self.pool, &plan, false)
                .await?
                .is_some_and(|r| r == audit.proof.source || matches_committed(&r, &audit.proof));
            if !copy_target {
                return Ok(
                    serde_json::json!({"mode":"raw_request_reference_dry_run","request_id":plan.request_id,"eligible":root_matches && source_matches,"source_deleted":false,"gc_authorized":false}),
                );
            }
            if !root_matches || !source_matches {
                return Err("raw source changed during target copy; source retained".into());
            }
        }
        let proof_bytes = serde_json::to_vec(&audit.proof)?;
        let proof_digest = blake3::hash(&proof_bytes).to_hex().to_string();
        let receipt_path = Path::from(format!(
            "migration-receipts/conversation-v1/{}/raw-request/{proof_digest}.json",
            self.identity
        ));
        match target_client
            .put_opts(
                &receipt_path,
                PutPayload::from_bytes(Bytes::from(proof_bytes.clone())),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(_) => {}
            Err(object_store::Error::AlreadyExists { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        let receipt = target_client.get(&receipt_path).await?;
        if receipt.meta.size != proof_bytes.len() as u64
            || receipt.bytes().await?.as_ref() != proof_bytes
        {
            return Err("immutable raw proof receipt mismatch".into());
        }
        if copy_target {
            // This proves only this immutable raw body. It is not a root/SQL
            // cutover, a source-release proof, or a globally verified snapshot.
            if !matches!(
                audit.status.as_str(),
                "committed" | "committed_confirmed_by_reread"
            ) {
                audit.status = "target_verified".into();
            }
            save_checkpoint(&audit_path, &audit)?;
            return Ok(serde_json::json!({
                "mode":"copy_raw_request_target","request_id":plan.request_id,
                "status":audit.status,"body_bytes":bare.size_bytes,
                "source_streamed":uploaded,"target_reused":!uploaded,
                "target_cas_creation_measured":false,"raw_body_verified":true,
                "source_writers_quiesced":false,
                "root_changed":false,"sql_changed":false,
                "source_deleted":false,"gc_authorized":false,"global_verified":false
            }));
        }
        save_checkpoint(&audit_path, &audit)?;
        let new_root = serde_json::to_vec(&audit.proof.target)?;
        let (current, _, _) = root(source_client.as_ref(), &root_path).await?;
        if current.as_ref() != new_root {
            if current.as_ref() != audit.proof.root_bytes {
                audit.status = "root_conflict".into();
                save_checkpoint(&audit_path, &audit)?;
                return Err("raw source root changed; preserved".into());
            }
            let update = source_client
                .put_opts(
                    &root_path,
                    PutPayload::from_bytes(Bytes::from(new_root.clone())),
                    PutOptions {
                        mode: PutMode::Update(UpdateVersion {
                            e_tag: audit.proof.root_etag.clone(),
                            version: audit.proof.root_version.clone(),
                        }),
                        ..Default::default()
                    },
                )
                .await;
            // Includes transport/commit-unknown: only an exact re-read permits SQL.
            let (observed, _, _) = root(source_client.as_ref(), &root_path).await?;
            if observed.as_ref() != new_root {
                audit.status = "root_update_unconfirmed".into();
                save_checkpoint(&audit_path, &audit)?;
                return match update {
                    Err(e) => Err(at_stage("raw_root_conditional_put", e)),
                    Ok(_) => Err("raw root readback conflict".into()),
                };
            }
        }
        audit.status = "root_relocated".into();
        save_checkpoint(&audit_path, &audit)?;
        let mut tx = self.pool.begin().await?;
        let current = row(&mut *tx, &plan, true).await?;
        let Some(current) = current else {
            tx.rollback().await?;
            audit.status = "row_missing_after_root".into();
            save_checkpoint(&audit_path, &audit)?;
            return Ok(report(&audit));
        };
        if matches_committed(&current, &audit.proof) {
            tx.rollback().await?;
            audit.status = "committed_confirmed_by_reread".into();
            save_checkpoint(&audit_path, &audit)?;
            return Ok(report(&audit));
        }
        if current != audit.proof.source {
            tx.rollback().await?;
            audit.status = "row_changed_after_root".into();
            save_checkpoint(&audit_path, &audit)?;
            return Ok(report(&audit));
        }
        let changed=sqlx::query("UPDATE request_records SET request_object=$1 WHERE tenant_id=$2 AND id=$3 AND request_object=$4")
            .bind(&audit.proof.target.object_locator).bind(&current.tenant_id).bind(&current.request_id).bind(&current.request_object).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err("locked raw source row changed".into());
        }
        match tx.commit().await {
            Ok(()) => audit.status = "committed".into(),
            Err(error) => {
                if row(&self.pool, &plan, false)
                    .await?
                    .is_some_and(|r| matches_committed(&r, &audit.proof))
                {
                    audit.status = "committed_confirmed_by_reread".into();
                } else {
                    return Err(error.into());
                }
            }
        }
        save_checkpoint(&audit_path, &audit)?;
        Ok(report(&audit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn raw_root_conditional_relocation_retains_source_and_recovers_without_overwriting_changes()
     {
        let admin_url = std::env::var("MTC_TEST_POSTGRES_URL").unwrap();
        let admin = PgPool::connect(&admin_url).await.unwrap();
        let name = format!("raw_refs_{}", Uuid::now_v7().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&admin_url).unwrap();
        url.set_path(&name);
        let pool = PgPool::connect(url.as_str()).await.unwrap();
        sqlx::raw_sql("CREATE TABLE request_records(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,key_id TEXT NOT NULL,reservation_id TEXT NOT NULL,created_at BIGINT NOT NULL,completed_at BIGINT,request_object TEXT NOT NULL)").execute(&pool).await.unwrap();
        let mut config = Config::for_test(url.to_string());
        config.archive_backend = memeloop_token_center::config::ArchiveBackend::S3;
        config.s3_endpoint = Some(std::env::var("MTC_RUSTFS_TEST_ENDPOINT").unwrap());
        config.s3_bucket = Some(std::env::var("MTC_RUSTFS_TEST_BUCKET").unwrap());
        config.s3_access_key = Some(std::env::var("MTC_RUSTFS_TEST_ACCESS_KEY").unwrap());
        config.s3_secret_key = Some(std::env::var("MTC_RUSTFS_TEST_SECRET_KEY").unwrap());
        config.s3_region = "us-east-1".into();
        config.s3_allow_http = true;
        let target_client = client(&config).unwrap();
        // Independent prefixes in the real isolated RustFS bucket are distinct
        // fixture stores; production constructs clients from actual endpoints.
        let source_client: Arc<dyn ObjectStore> = Arc::new(object_store::prefix::PrefixStore::new(
            target_client.clone(),
            format!("raw-source-{}", Uuid::now_v7().simple()),
        ));
        let mut source_config = config.clone();
        source_config.s3_endpoint = Some("http://source-fixture.invalid:9000".into());
        let directory = tempfile::tempdir().unwrap();
        let runner = Runner {
            pool: pool.clone(),
            source: None,
            target: ArchiveStore::from_config(&config).await.unwrap(),
            checkpoint: directory.path().join("raw.json"),
            identity: "raw-test-identity".into(),
        };
        let tenant = Uuid::now_v7();
        let request = Uuid::now_v7();
        let body = Bytes::from(format!(
            "{{\"request\":\"{request}\",\"text\":\"{}\"}}",
            "raw byte proof".repeat(20000)
        ));
        let original = runner
            .target
            .put_tenant_content(tenant, body.clone())
            .await
            .unwrap();
        source_client
            .put(
                &Path::from(original.object_locator.as_str()),
                PutPayload::from_bytes(body.clone()),
            )
            .await
            .unwrap();
        let root_path = Path::from(format!("tenants/{tenant}/raw/v1/{request}/request.json"));
        let original_encoded = serde_json::to_vec(&original).unwrap();
        source_client
            .put(
                &root_path,
                PutPayload::from_bytes(Bytes::from(original_encoded.clone())),
            )
            .await
            .unwrap();
        sqlx::query("INSERT INTO request_records VALUES($1,$2,'key','reservation',1,2,$3)")
            .bind(request.to_string())
            .bind(tenant.to_string())
            .bind(&original.object_locator)
            .execute(&pool)
            .await
            .unwrap();
        let training = blake3::hash(
            &serde_json::to_vec(&(
                "mtc-training-s3-v1",
                config.s3_endpoint.as_ref().unwrap(),
                config.s3_bucket.as_ref().unwrap(),
                &config.s3_region,
            ))
            .unwrap(),
        )
        .to_hex()
        .to_string();
        let plan = RawRequestPlan {
            tenant_id: tenant,
            request_id: request,
            target_locator: format!("stores/training/{training}/{}", original.object_locator),
        };
        // Copy and pointer mutation are separate operations. This fixture uses
        // an independent memory body source and real RustFS roots/target, while
        // production builds both source clients from one explicit S3 config.
        let body_source = ArchiveStore::from_config(&Config::for_test(url.to_string()))
            .await
            .unwrap();
        assert_eq!(
            body_source
                .put_tenant_content(tenant, body.clone())
                .await
                .unwrap(),
            original
        );
        let copy_runner = Runner {
            pool: pool.clone(),
            source: Some(body_source),
            target: runner.target.clone(),
            checkpoint: directory.path().join("raw-copy.json"),
            identity: runner.identity.clone(),
        };
        // Gaps cannot be filled from a semantically similar document.
        sqlx::query("UPDATE request_records SET request_object=$1 WHERE id=$2")
            .bind(format!("gap://{request}/request"))
            .bind(request.to_string())
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            Box::pin(copy_runner.relocate_raw_request_with_clients(
                &config,
                &source_config,
                plan.clone(),
                RawAction::CopyTarget,
                source_client.clone(),
                target_client.clone(),
            ))
            .await
            .is_err()
        );
        sqlx::query("UPDATE request_records SET request_object=$1 WHERE id=$2")
            .bind(&original.object_locator)
            .bind(request.to_string())
            .execute(&pool)
            .await
            .unwrap();
        // Only isolated fixture injection removes the target to test a miss.
        target_client
            .delete(&Path::from(original.object_locator.as_str()))
            .await
            .unwrap();
        let copied = Box::pin(copy_runner.relocate_raw_request_with_clients(
            &config,
            &source_config,
            plan.clone(),
            RawAction::CopyTarget,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(copied["source_streamed"], true);
        assert_eq!(copied["sql_changed"], false);
        assert_eq!(copied["root_changed"], false);
        assert_eq!(copied["gc_authorized"], false);
        assert_eq!(
            row(&pool, &plan, false)
                .await
                .unwrap()
                .unwrap()
                .request_object,
            original.object_locator
        );
        assert_eq!(
            root(source_client.as_ref(), &root_path)
                .await
                .unwrap()
                .0
                .as_ref(),
            original_encoded
        );
        assert_eq!(
            runner
                .target
                .get_tenant_content(tenant, &original, body.len())
                .await
                .unwrap(),
            body
        );
        let metadata_before = target_client
            .head(&Path::from(original.object_locator.as_str()))
            .await
            .unwrap();
        let reused = Box::pin(copy_runner.relocate_raw_request_with_clients(
            &config,
            &source_config,
            plan.clone(),
            RawAction::CopyTarget,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(reused["target_reused"], true);
        assert_eq!(reused["source_streamed"], false);
        let metadata_after = target_client
            .head(&Path::from(original.object_locator.as_str()))
            .await
            .unwrap();
        assert_eq!(metadata_after.last_modified, metadata_before.last_modified);
        assert_eq!(metadata_after.e_tag, metadata_before.e_tag);
        // Compression changes the physical representation, never the raw bytes
        // or request/root identity. No semantic-normalized body is substituted.
        let compressed_plan = RawRequestPlan {
            target_locator: format!("{}.mtcz1", plan.target_locator),
            ..plan.clone()
        };
        let compressed_runner = Runner {
            checkpoint: directory.path().join("raw-copy-compressed.json"),
            ..copy_runner
        };
        let compressed = Box::pin(compressed_runner.relocate_raw_request_with_clients(
            &config,
            &source_config,
            compressed_plan.clone(),
            RawAction::CopyTarget,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(compressed["source_streamed"], true);
        let compressed_object = CasArchiveObject {
            object_locator: format!("{}.mtcz1", original.object_locator),
            ..original.clone()
        };
        assert_eq!(
            runner
                .target
                .get_tenant_content(tenant, &compressed_object, body.len())
                .await
                .unwrap(),
            body
        );
        assert_eq!(
            root(source_client.as_ref(), &root_path)
                .await
                .unwrap()
                .0
                .as_ref(),
            original_encoded
        );
        let dry = Box::pin(runner.relocate_raw_request_with_clients(
            &config,
            &source_config,
            plan.clone(),
            RawAction::Verify,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(dry["eligible"], true);
        assert_eq!(
            root(source_client.as_ref(), &root_path)
                .await
                .unwrap()
                .0
                .as_ref(),
            original_encoded
        );
        assert!(
            !runner
                .checkpoint
                .with_extension("raw-request-audit.json")
                .exists()
        );
        // Two distinct requests share one immutable target. Batch cursors must not
        // repeat completed work, and changing the plan must fail closed.
        let mut batch_requests = Vec::new();
        for _ in 0..2 {
            let id = Uuid::now_v7();
            sqlx::query("INSERT INTO request_records SELECT $1,tenant_id,key_id,reservation_id,created_at,completed_at,request_object FROM request_records WHERE id=$2")
                .bind(id.to_string()).bind(request.to_string()).execute(&pool).await.unwrap();
            source_client
                .put(
                    &Path::from(format!("tenants/{tenant}/raw/v1/{id}/request.json")),
                    PutPayload::from_bytes(Bytes::from(original_encoded.clone())),
                )
                .await
                .unwrap();
            batch_requests.push(RawRequestPlan {
                request_id: id,
                ..plan.clone()
            });
        }
        let batch_runner = Runner {
            pool: pool.clone(),
            source: compressed_runner.source.clone(),
            target: runner.target.clone(),
            checkpoint: directory.path().join("batch.json"),
            identity: runner.identity.clone(),
        };
        let copied_batch = Box::pin(batch_runner.raw_batch_with_clients(
            &config,
            &source_config,
            RawBatchPlan {
                requests: batch_requests.clone(),
            },
            true,
            false,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(copied_batch["completed"], 2);
        assert_eq!(copied_batch["target_reused_requests"], 2);
        assert_eq!(copied_batch["unique_target_objects"], 1);
        assert_eq!(copied_batch["unique_target_bytes"], body.len() as u64);
        assert_eq!(copied_batch["source_streamed_requests"], 0);
        let applied_batch = Box::pin(batch_runner.raw_batch_with_clients(
            &config,
            &source_config,
            RawBatchPlan {
                requests: batch_requests.clone(),
            },
            false,
            true,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(applied_batch["completed"], 2);
        assert_eq!(applied_batch["reference_bytes"], (body.len() * 2) as u64);
        for member in &batch_requests {
            assert_eq!(
                row(&pool, member, false)
                    .await
                    .unwrap()
                    .unwrap()
                    .request_object,
                plan.target_locator
            );
        }
        let resumed = Box::pin(batch_runner.raw_batch_with_clients(
            &config,
            &source_config,
            RawBatchPlan {
                requests: batch_requests.clone(),
            },
            false,
            true,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(resumed, applied_batch);
        // A completed cursor must reject store drift before skipping children.
        for target_drift in [false, true] {
            let mut changed_source = source_config.clone();
            let mut changed_target = config.clone();
            if target_drift {
                changed_target.s3_region = "changed-region".into();
            } else {
                changed_source.s3_endpoint = Some("http://changed-source.invalid".into());
            }
            assert!(
                Box::pin(batch_runner.raw_batch_with_clients(
                    &changed_target,
                    &changed_source,
                    RawBatchPlan {
                        requests: batch_requests.clone()
                    },
                    false,
                    true,
                    source_client.clone(),
                    target_client.clone()
                ))
                .await
                .is_err()
            );
        }
        // An interrupted cursor is subject to the same full-store binding.
        let cursor_path = batch_runner
            .checkpoint
            .with_extension("raw-batch-apply.json");
        let mut partial: RawBatchProgress =
            serde_json::from_reader(std::fs::File::open(&cursor_path).unwrap()).unwrap();
        partial.next = 1;
        save_checkpoint(&cursor_path, &partial).unwrap();
        let mut changed_source = source_config.clone();
        changed_source.s3_region = "changed-source-region".into();
        assert!(
            Box::pin(batch_runner.raw_batch_with_clients(
                &config,
                &changed_source,
                RawBatchPlan {
                    requests: batch_requests.clone()
                },
                false,
                true,
                source_client.clone(),
                target_client.clone()
            ))
            .await
            .is_err()
        );
        let mut changed_target = config.clone();
        changed_target.s3_endpoint = Some("http://changed-target.invalid".into());
        assert!(
            Box::pin(batch_runner.raw_batch_with_clients(
                &changed_target,
                &source_config,
                RawBatchPlan {
                    requests: batch_requests.clone()
                },
                false,
                true,
                source_client.clone(),
                target_client.clone()
            ))
            .await
            .is_err()
        );
        batch_requests.reverse();
        assert!(
            Box::pin(batch_runner.raw_batch_with_clients(
                &config,
                &source_config,
                RawBatchPlan {
                    requests: batch_requests.clone()
                },
                false,
                true,
                source_client.clone(),
                target_client.clone()
            ))
            .await
            .is_err()
        );
        batch_requests.push(batch_requests[0].clone());
        assert!(
            validate_batch(&RawBatchPlan {
                requests: batch_requests
            })
            .is_err()
        );
        let applied = Box::pin(runner.relocate_raw_request_with_clients(
            &config,
            &source_config,
            plan.clone(),
            RawAction::Apply,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(applied["status"], "committed");
        let rechecked = Box::pin(runner.relocate_raw_request_with_clients(
            &config,
            &source_config,
            plan.clone(),
            RawAction::CopyTarget,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(
            rechecked["status"], "committed",
            "copy readback must not downgrade a committed audit"
        );
        assert_eq!(rechecked["target_reused"], true);

        assert_eq!(applied["source_deleted"], false);
        assert_eq!(applied["gc_authorized"], false);
        let published: CasArchiveObject =
            serde_json::from_slice(&root(source_client.as_ref(), &root_path).await.unwrap().0)
                .unwrap();
        assert_eq!(published.object_locator, plan.target_locator);
        assert_eq!(published.blake3_digest, original.blake3_digest);
        assert_eq!(published.size_bytes, original.size_bytes);
        let current = row(&pool, &plan, false).await.unwrap().unwrap();
        assert_eq!(current.request_object, plan.target_locator);
        assert_eq!(current.key_id, "key");
        assert_eq!(current.reservation_id, "reservation");
        assert_eq!(
            source_client
                .get(&Path::from(original.object_locator.as_str()))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
            body
        );
        let audit_path = runner.checkpoint.with_extension("raw-request-audit.json");
        let mut audit: RawAudit =
            serde_json::from_reader(std::fs::File::open(&audit_path).unwrap()).unwrap();
        // Crash after root commit but before SQL commit: same durable proof,
        // root already relocated, original SQL restored as the crash boundary.
        sqlx::query("UPDATE request_records SET request_object=$1 WHERE id=$2")
            .bind(&original.object_locator)
            .bind(request.to_string())
            .execute(&pool)
            .await
            .unwrap();
        audit.status = "root_relocated".into();
        save_checkpoint(&audit_path, &audit).unwrap();
        let recovered = Box::pin(runner.relocate_raw_request_with_clients(
            &config,
            &source_config,
            plan.clone(),
            RawAction::Apply,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(recovered["status"], "committed");
        let replay = Box::pin(runner.relocate_raw_request_with_clients(
            &config,
            &source_config,
            plan.clone(),
            RawAction::Apply,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(replay["status"], "committed_confirmed_by_reread");
        let mut wrong_plan = plan.clone();
        wrong_plan.request_id = Uuid::now_v7();
        assert!(
            Box::pin(runner.relocate_raw_request_with_clients(
                &config,
                &source_config,
                wrong_plan,
                RawAction::Apply,
                source_client.clone(),
                target_client.clone()
            ))
            .await
            .is_err()
        );
        // An unrelated current identity is never overwritten, even though the
        // root successfully relocated before its SQL version was rechecked.
        sqlx::query(
            "UPDATE request_records SET request_object=$1,key_id='changed-key' WHERE id=$2",
        )
        .bind(&original.object_locator)
        .bind(request.to_string())
        .execute(&pool)
        .await
        .unwrap();
        let changed = Box::pin(runner.relocate_raw_request_with_clients(
            &config,
            &source_config,
            plan.clone(),
            RawAction::Apply,
            source_client.clone(),
            target_client.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(changed["status"], "row_changed_after_root");
        assert_eq!(
            row(&pool, &plan, false)
                .await
                .unwrap()
                .unwrap()
                .request_object,
            original.object_locator
        );
        // Fault injection touches only this isolated fixture body, bypassing
        // ArchiveStore's production immutable CAS overwrite prohibition.
        target_client
            .put(
                &Path::from(original.object_locator.as_str()),
                PutPayload::from_bytes(Bytes::from_static(b"bad target")),
            )
            .await
            .unwrap();
        assert!(
            Box::pin(runner.relocate_raw_request_with_clients(
                &config,
                &source_config,
                plan.clone(),
                RawAction::CopyTarget,
                source_client.clone(),
                target_client.clone(),
            ))
            .await
            .is_err(),
            "copy mode must not overwrite an existing corrupt CAS"
        );
        assert_eq!(
            target_client
                .get(&Path::from(original.object_locator.as_str()))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
            Bytes::from_static(b"bad target")
        );

        assert!(
            Box::pin(runner.relocate_raw_request_with_clients(
                &config,
                &source_config,
                plan.clone(),
                RawAction::Apply,
                source_client.clone(),
                target_client.clone()
            ))
            .await
            .is_err()
        );
        target_client
            .put(
                &Path::from(original.object_locator.as_str()),
                PutPayload::from_bytes(body),
            )
            .await
            .unwrap();
        let (_, old_etag, old_version) = root(source_client.as_ref(), &root_path).await.unwrap();
        let third_party = Bytes::from_static(br#"{"third_party":"do not overwrite"}"#);
        source_client
            .put(&root_path, PutPayload::from_bytes(third_party.clone()))
            .await
            .unwrap();
        assert!(
            source_client
                .put_opts(
                    &root_path,
                    PutPayload::from_bytes(Bytes::from(original_encoded)),
                    PutOptions {
                        mode: PutMode::Update(UpdateVersion {
                            e_tag: old_etag,
                            version: old_version
                        }),
                        ..Default::default()
                    }
                )
                .await
                .is_err()
        );
        assert!(
            Box::pin(runner.relocate_raw_request_with_clients(
                &config,
                &source_config,
                plan,
                RawAction::Apply,
                source_client.clone(),
                target_client
            ))
            .await
            .is_err()
        );
        assert_eq!(
            root(source_client.as_ref(), &root_path).await.unwrap().0,
            third_party
        );
        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
