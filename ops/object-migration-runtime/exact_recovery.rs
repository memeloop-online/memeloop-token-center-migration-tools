use super::*;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    locator: String,
    decoded_bytes: u64,
    decoded_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    format_version: u32,
    tenant_id: Uuid,
    key_id: Uuid,
    request_id: Uuid,
    expected_projected_at: i64,
    request: Source,
    response: Source,
}

async fn verify_source(archive: &ArchiveStore, expected: &Source) -> Result<()> {
    if expected.decoded_sha256.len() != 64
        || !expected
            .decoded_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid exact recovery source digest".into());
    }
    let mut download = archive.open_stream(&expected.locator, None).await?;
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    while let Some(chunk) = download.stream.next().await {
        let chunk = chunk?;
        bytes = bytes
            .checked_add(chunk.len() as u64)
            .ok_or("source size overflow")?;
        hash.update(&chunk);
    }
    if bytes != expected.decoded_bytes
        || format!("{:x}", hash.finalize()) != expected.decoded_sha256.to_ascii_lowercase()
    {
        return Err("exact recovery source bytes changed".into());
    }
    Ok(())
}

pub(super) async fn run(plan_path: &std::path::Path, receipt_path: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(plan_path)?;
    let plan: Plan = serde_json::from_slice(&bytes)?;
    if plan.format_version != 1 || plan.request.locator == plan.response.locator {
        return Err("invalid exact recovery plan".into());
    }
    let mut config = Config::from_env().map_err(|e| at_stage("exact_configuration", e))?;
    // An exact content repair must not perform startup schema migrations.
    config.run_migrations_on_start = false;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&config.database_url)
        .await?;
    let state = memeloop_token_center::AppState::initialize(config)
        .await
        .map_err(|e| at_stage("exact_initialize", e))?;
    verify_source(&state.archive, &plan.request)
        .await
        .map_err(|e| at_stage("exact_request_source", e))?;
    verify_source(&state.archive, &plan.response)
        .await
        .map_err(|e| at_stage("exact_response_source", e))?;
    let identity = blake3::hash(&bytes).to_hex().to_string();
    let mut receipt: serde_json::Value = if receipt_path.exists() {
        let previous: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(receipt_path)?)?;
        if previous["identity"].as_str() != Some(identity.as_str()) {
            return Err("exact recovery receipt belongs to a different plan".into());
        }
        previous
    } else {
        serde_json::json!({
            "format_version":1, "identity":identity, "request_id":plan.request_id,
            "source_bytes_verified":true, "claimed":false, "canonical_rebuilt":false,
            "financial_replay":false, "old_source_retired":false,
            "complete":false, "api_readback_verified":false
        })
    };
    // The ordinary writer prefers durable raw roots. Verify those actual
    // selected sources against exactly the same decoded-byte contract.
    for (side, expected) in [("request", &plan.request), ("response", &plan.response)] {
        if let Some(root) = state
            .archive
            .raw_capture_reference(plan.tenant_id, plan.request_id, side)
            .await?
        {
            verify_source(
                &state.archive,
                &Source {
                    locator: root.object_locator,
                    decoded_bytes: expected.decoded_bytes,
                    decoded_sha256: expected.decoded_sha256.clone(),
                },
            )
            .await?;
        }
    }
    let row = sqlx::query("SELECT o.projected_at, o.semantic_snapshot_json, r.request_object, r.response_object FROM conversation_projection_outbox o JOIN request_records r ON r.id = o.request_id AND r.tenant_id = o.tenant_id AND r.key_id = o.key_id WHERE o.request_id = $1 AND o.tenant_id = $2 AND o.key_id = $3")
        .bind(plan.request_id.to_string()).bind(plan.tenant_id.to_string()).bind(plan.key_id.to_string())
        .fetch_one(&pool).await?;
    let current_request: String = row.try_get("request_object")?;
    let current_response: Option<String> = row.try_get("response_object")?;
    let current_response = current_response.ok_or("exact response source disappeared")?;
    // The normal writer may durably bind an equivalent raw-root CAS locator
    // before preparation. Resume only after independently hashing that current
    // selected content against the original immutable plan.
    for (locator, expected) in [
        (&current_request, &plan.request),
        (&current_response, &plan.response),
    ] {
        verify_source(
            &state.archive,
            &Source {
                locator: locator.clone(),
                decoded_bytes: expected.decoded_bytes,
                decoded_sha256: expected.decoded_sha256.clone(),
            },
        )
        .await
        .map_err(|e| at_stage("exact_current_source", e))?;
    }
    receipt["current_source_locators"] =
        serde_json::json!({"request":current_request,"response":current_response});
    let current_ack: Option<i64> = row.try_get("projected_at")?;
    let current_snapshot: Option<String> = row.try_get("semantic_snapshot_json")?;
    let already_written = current_ack.is_some() && current_snapshot.is_some();
    let projected = if already_written {
        if receipt["claim_intent"].as_bool() != Some(true) {
            return Err(
                "unexpected existing canonical content; exact recovery will not overwrite it"
                    .into(),
            );
        }
        true
    } else {
        let expected_ack =
            if receipt["claim_intent"].as_bool() == Some(true) && current_ack.is_none() {
                None
            } else {
                Some(plan.expected_projected_at)
            };
        let owner = Uuid::now_v7();
        // Persist intent before the CAS so an interrupted result can be resumed
        // after the existing finite lease expires, without changing the plan.
        receipt["claim_intent"] = true.into();
        save_checkpoint(receipt_path, &receipt)?;
        let claimed = state
            .db
            .claim_exact_session_body_rebuild(
                plan.tenant_id,
                plan.key_id,
                plan.request_id,
                expected_ack,
                &current_request,
                &current_response,
                owner,
                current_snapshot.as_deref(),
                receipt["lease_owner"]
                    .as_str()
                    .map(Uuid::parse_str)
                    .transpose()?,
            )
            .await?;
        if !claimed {
            return Err("exact recovery source/acknowledgement/lease CAS did not match".into());
        }
        receipt["claimed"] = true.into();
        receipt["lease_owner"] = owner.to_string().into();
        save_checkpoint(receipt_path, &receipt)?;
        memeloop_token_center::worker::archive_session_body(&state, owner, plan.request_id)
            .await
            .map_err(|e| at_stage("exact_canonical_writer", e))?
    };
    // Re-read all original bytes after publication; no source is deleted here.
    verify_source(&state.archive, &plan.request)
        .await
        .map_err(|e| at_stage("exact_request_source", e))?;
    verify_source(&state.archive, &plan.response)
        .await
        .map_err(|e| at_stage("exact_response_source", e))?;
    let row = sqlx::query(
        "SELECT semantic_snapshot_json, (SELECT o.leaf_node_hash FROM conversation_observations o JOIN conversation_clusters c ON c.id = o.cluster_id WHERE o.request_id = $1 AND c.tenant_id = $2 AND o.key_id = $3 LIMIT 1) AS leaf_node_hash FROM conversation_projection_outbox
         WHERE request_id = $1 AND tenant_id = $2 AND key_id = $3",
    )
    .bind(plan.request_id.to_string())
    .bind(plan.tenant_id.to_string())
    .bind(plan.key_id.to_string())
    .fetch_optional(&pool)
    .await?;
    let observation_leaf: Option<String> = row
        .as_ref()
        .map(|r| r.try_get("leaf_node_hash"))
        .transpose()?
        .flatten();
    let snapshot: Option<String> = row
        .map(|r| r.try_get("semantic_snapshot_json"))
        .transpose()?
        .flatten();
    let snapshot: Option<serde_json::Value> =
        snapshot.as_deref().map(serde_json::from_str).transpose()?;
    let leaf = snapshot
        .as_ref()
        .and_then(|v| v.get("leaf"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .or(observation_leaf);
    if let Some(leaf) = leaf.as_deref() {
        let authority = state
            .archive
            .semantic_archive_authority(plan.tenant_id, plan.request_id, leaf)
            .await?
            .ok_or("canonical manifest is not reachable from committed leaf")?;
        let manifest = state
            .archive
            .get_semantic_manifest_streamed(plan.tenant_id, &authority.publication.manifest)
            .await?;
        let raw = manifest
            .raw_sources
            .as_ref()
            .ok_or("canonical manifest missing original provenance")?;
        verify_source(
            &state.archive,
            &Source {
                locator: raw.request.object_locator.clone(),
                decoded_bytes: plan.request.decoded_bytes,
                decoded_sha256: plan.request.decoded_sha256.clone(),
            },
        )
        .await?;
        let response = raw
            .response
            .as_ref()
            .ok_or("canonical manifest missing response provenance")?;
        verify_source(
            &state.archive,
            &Source {
                locator: response.object_locator.clone(),
                decoded_bytes: plan.response.decoded_bytes,
                decoded_sha256: plan.response.decoded_sha256.clone(),
            },
        )
        .await?;
        receipt["canonical_manifest_verified"] = true.into();
        receipt["coverage"] = serde_json::to_value(&manifest.coverage)?;
        receipt["publication"] = serde_json::to_value(&authority.publication)?;
    }
    receipt["canonical_rebuilt"] = (projected && leaf.is_some()).into();
    receipt["leaf_node_hash"] = serde_json::to_value(&leaf)?;
    receipt["source_bytes_reverified"] = true.into();
    // Content readback and the original terminal/incomplete state require an
    // independent API receipt. A writer acknowledgement cannot certify those.
    save_checkpoint(receipt_path, &receipt)?;
    println!("{}", serde_json::to_string(&receipt)?);
    if !projected || leaf.is_none() {
        return Err("exact recovery did not publish a canonical observation".into());
    }
    Ok(())
}
