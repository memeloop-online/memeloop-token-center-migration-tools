use super::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Deserialize, Serialize)]
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
    run_with_review(plan_path, receipt_path, None).await
}

async fn run_with_review(
    plan_path: &std::path::Path,
    receipt_path: &std::path::Path,
    reviewed_input: Option<(&serde_json::Value, &[u8])>,
) -> Result<()> {
    let current_bytes = std::fs::read(plan_path)?;
    let bytes = if let Some((_, verified)) = reviewed_input {
        require_same_plan_bytes(verified, &current_bytes)?;
        verified.to_vec()
    } else {
        current_bytes
    };
    let reviewed = reviewed_input.map(|(review, _)| review);
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
    let state = memeloop_token_center::AppState::initialize_for_maintenance(config)
        .await
        .map_err(|e| at_stage("exact_initialize", e))?;
    verify_source(&state.archive, &plan.request)
        .await
        .map_err(|e| at_stage("exact_request_source", e))?;
    verify_source(&state.archive, &plan.response)
        .await
        .map_err(|e| at_stage("exact_response_source", e))?;
    let identity = blake3::hash(&bytes).to_hex().to_string();
    let mut receipt: serde_json::Value = if reviewed.is_none() && receipt_path.exists() {
        let previous: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(receipt_path)?)?;
        reject_reviewed_receipt_in_ordinary_run(&previous)?;
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
    if let Some(review) = reviewed {
        receipt["intent_id"] = Uuid::now_v7().to_string().into();
        receipt["reviewed_handover"] = review.clone();
        // Reserve this output before any completed/claim branch. No existing
        // receipt can lend its intent or completion status to this invocation.
        save_inspection_noclobber(receipt_path, &receipt)?;
    }
    // The ordinary writer prefers durable raw roots. Verify those actual
    // selected sources against exactly the same decoded-byte contract.
    for (side, expected) in [("request", &plan.request), ("response", &plan.response)] {
        if let Some(root) = state
            .archive
            .raw_capture_reference(plan.tenant_id, plan.request_id, side)
            .await?
        {
            if let Some(review) = reviewed {
                let selected = &review["selected_sources"][side];
                if selected["selection"] != "raw_root"
                    || selected["reference"] != serde_json::to_value(&root)?
                {
                    return Err("reviewed selected raw reference changed".into());
                }
            }
            verify_source(
                &state.archive,
                &Source {
                    locator: root.object_locator,
                    decoded_bytes: expected.decoded_bytes,
                    decoded_sha256: expected.decoded_sha256.clone(),
                },
            )
            .await?;
        } else if reviewed
            .is_some_and(|review| review["selected_sources"][side]["selection"] != "request_record")
        {
            return Err("reviewed selected raw reference disappeared".into());
        }
    }
    let row = sqlx::query("SELECT o.projected_at, o.semantic_snapshot_json, r.request_object, r.response_object FROM conversation_projection_outbox o JOIN request_record_locators l ON l.id = o.request_id AND l.tenant_id = o.tenant_id AND l.key_id = o.key_id JOIN request_records r ON r.id = l.id AND r.created_at = l.created_at AND r.tenant_id = l.tenant_id AND r.key_id = l.key_id WHERE o.request_id = $1 AND o.tenant_id = $2 AND o.key_id = $3")
        .bind(plan.request_id.to_string()).bind(plan.tenant_id.to_string()).bind(plan.key_id.to_string())
        .fetch_one(&pool).await?;
    let current_request: String = row.try_get("request_object")?;
    let current_response: Option<String> = row.try_get("response_object")?;
    let current_response = current_response.ok_or("exact response source disappeared")?;
    if let Some(review) = reviewed {
        if review["request"]["locator"].as_str() != Some(current_request.as_str())
            || review["response"]["locator"].as_str() != Some(current_response.as_str())
        {
            return Err("reviewed source locator changed".into());
        }
    }
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
        if reviewed.is_some() {
            return Err(
                "completed-unattributed: reviewed invocation did not perform this publication"
                    .into(),
            );
        }
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
        if current_snapshot.is_some() && reviewed.is_none() {
            return Err("prepared recovery requires a reviewed handover; inspection only".into());
        }
        let owner = Uuid::now_v7();
        // Persist intent before the CAS so an interrupted result can be resumed
        // after the existing finite lease expires, without changing the plan.
        receipt["claim_intent"] = true.into();
        if reviewed.is_some() {
            receipt["lease_owner"] = owner.to_string().into();
        }
        save_checkpoint(receipt_path, &receipt)?;
        let claimed = if let Some(review) = reviewed {
            let snapshot = current_snapshot
                .as_deref()
                .ok_or("reviewed snapshot disappeared")?;
            if review["snapshot_sha256"].as_str()
                != Some(format!("{:x}", Sha256::digest(snapshot.as_bytes())).as_str())
            {
                return Err("reviewed snapshot changed".into());
            }
            state
                .db
                .claim_reviewed_session_body_rebuild(
                    plan.tenant_id,
                    plan.key_id,
                    plan.request_id,
                    &current_request,
                    &current_response,
                    owner,
                    snapshot,
                    Uuid::parse_str(
                        review["expected_owner"]
                            .as_str()
                            .ok_or("reviewed owner missing")?,
                    )?,
                    review["created_at"]
                        .as_i64()
                        .ok_or("reviewed creation identity missing")?,
                    review["expected_lease_expires_at"]
                        .as_i64()
                        .ok_or("reviewed expiry missing")?,
                )
                .await?
        } else {
            state
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
                .await?
        };
        if !claimed {
            return Err("exact recovery source/acknowledgement/lease CAS did not match".into());
        }
        receipt["claimed"] = true.into();
        receipt["lease_owner"] = owner.to_string().into();
        save_checkpoint(receipt_path, &receipt)?;
        memeloop_token_center::worker::recover_claimed_session_body(&state, owner, plan.request_id)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn equivalent_rebound_locator_must_match_original_decoded_bytes() {
        let archive = ArchiveStore::from_config(&Config::for_test("sqlite::memory:".into()))
            .await
            .unwrap();
        let tenant = Uuid::now_v7();
        let bytes = Bytes::from_static(br#"{"input":"original request"}"#);
        archive
            .put("legacy/request.json", bytes.clone())
            .await
            .unwrap();
        let original = Source {
            locator: "legacy/request.json".into(),
            decoded_bytes: bytes.len() as u64,
            decoded_sha256: format!("{:x}", Sha256::digest(&bytes)),
        };
        verify_source(&archive, &original).await.unwrap();
        let rebound = archive
            .put_tenant_content(tenant, bytes.clone())
            .await
            .unwrap();
        assert_ne!(rebound.object_locator, original.locator);
        verify_source(
            &archive,
            &Source {
                locator: rebound.object_locator.clone(),
                decoded_bytes: original.decoded_bytes,
                decoded_sha256: original.decoded_sha256.clone(),
            },
        )
        .await
        .unwrap();
        archive
            .put(
                "legacy/changed.json",
                Bytes::from_static(br#"{"input":"different source"}"#),
            )
            .await
            .unwrap();
        assert!(
            verify_source(
                &archive,
                &Source {
                    locator: "legacy/changed.json".into(),
                    decoded_bytes: original.decoded_bytes,
                    decoded_sha256: original.decoded_sha256
                }
            )
            .await
            .is_err()
        );
        assert_eq!(archive.get(&original.locator).await.unwrap(), bytes);
    }
}

/// Build a separate handover candidate. This never claims, clears a snapshot,
/// starts application workers, or edits the previous recovery receipt.
pub(super) async fn resume_reviewed(
    plan_path: &std::path::Path,
    prior_path: &std::path::Path,
    handover_path: &std::path::Path,
    output: &std::path::Path,
) -> Result<()> {
    if output == plan_path || output == prior_path || output == handover_path {
        return Err("reviewed intent requires an independent output".into());
    }
    if output.exists() {
        // Preserve an uncertain prior claim rather than selecting another owner.
        return Err(
            "existing reviewed intent requires read-only reconciliation; no claim repeated".into(),
        );
    }
    let plan_bytes = std::fs::read(plan_path)?;
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    let identity = blake3::hash(&plan_bytes).to_hex().to_string();
    let prior_bytes = std::fs::read(prior_path)?;
    let prior: serde_json::Value = serde_json::from_slice(&prior_bytes)?;
    if prior["identity"].as_str() != Some(identity.as_str())
        || prior["claim_intent"].as_bool() != Some(true)
    {
        return Err("original intent does not match reviewed plan".into());
    }
    let review: serde_json::Value = serde_json::from_slice(&std::fs::read(handover_path)?)?;
    let config = Config::from_env()?;
    let archive = ArchiveStore::from_config(&config).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&config.database_url)
        .await?;
    let fresh = inspect_verified(&pool, &archive, &plan, &identity, &prior_bytes).await?;
    pool.close().await;
    validate_reviewed_handover(&review, &fresh)?;
    run_with_review(plan_path, output, Some((&review, &plan_bytes))).await
}

fn reject_reviewed_receipt_in_ordinary_run(receipt: &serde_json::Value) -> Result<()> {
    if receipt.get("reviewed_handover").is_some() || receipt.get("intent_id").is_some() {
        return Err("reviewed intent requires read-only reconciliation; ordinary recovery cannot claim or acknowledge it".into());
    }
    Ok(())
}

fn require_same_plan_bytes(verified: &[u8], current: &[u8]) -> Result<()> {
    if verified != current {
        return Err("reviewed plan file changed".into());
    }
    Ok(())
}

fn validate_reviewed_handover(review: &serde_json::Value, fresh: &serde_json::Value) -> Result<()> {
    if review["kind"] != "exact_recovery_inspection"
        || review["ready_for_review"] != true
        || fresh["ready_for_review"] != true
        || review != fresh
    {
        return Err(
            "reviewed recovery state or selected source changed; inspection required".into(),
        );
    }
    Ok(())
}

pub(super) async fn inspect(
    plan_path: &std::path::Path,
    prior_receipt_path: &std::path::Path,
    output: &std::path::Path,
) -> Result<()> {
    if output.exists() || output == prior_receipt_path || output == plan_path {
        return Err("inspection output must be a new independent receipt".into());
    }
    let plan_bytes = std::fs::read(plan_path)?;
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    if plan.format_version != 1 || plan.request.locator == plan.response.locator {
        return Err("invalid exact recovery plan".into());
    }
    let prior_bytes = std::fs::read(prior_receipt_path)?;
    let prior: serde_json::Value = serde_json::from_slice(&prior_bytes)?;
    let identity = blake3::hash(&plan_bytes).to_hex().to_string();
    if prior["identity"].as_str() != Some(identity.as_str())
        || prior["request_id"].as_str() != Some(plan.request_id.to_string().as_str())
        || prior["claim_intent"].as_bool() != Some(true)
    {
        return Err("original receipt does not identify this recovery intent".into());
    }
    let config = Config::from_env().map_err(|e| at_stage("inspect_configuration", e))?;
    let archive = ArchiveStore::from_config(&config).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&config.database_url)
        .await?;
    let receipt = inspect_verified(&pool, &archive, &plan, &identity, &prior_bytes).await?;
    save_inspection_noclobber(output, &receipt)?;
    pool.close().await;
    Ok(())
}

async fn inspect_verified(
    pool: &PgPool,
    archive: &ArchiveStore,
    plan: &Plan,
    identity: &str,
    prior_bytes: &[u8],
) -> Result<serde_json::Value> {
    let mut read = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *read)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='3s'")
        .execute(&mut *read)
        .await?;
    let row = sqlx::query("SELECT l.created_at, o.projected_at, o.semantic_snapshot_json,
        o.lease_owner, o.lease_expires_at, o.terminal_lease_owner, o.terminal_lease_expires_at,
        CAST(CASE WHEN o.semantic_payload_snapshot_json IS NOT NULL THEN 1 ELSE 0 END AS BIGINT) AS payload_present,
        r.request_object, r.response_object
        FROM conversation_projection_outbox o JOIN request_record_locators l
          ON l.id=o.request_id AND l.tenant_id=o.tenant_id AND l.key_id=o.key_id
        JOIN request_records r ON r.id=l.id AND r.created_at=l.created_at
          AND r.tenant_id=l.tenant_id AND r.key_id=l.key_id
        WHERE o.request_id=$1 AND o.tenant_id=$2 AND o.key_id=$3")
        .bind(plan.request_id.to_string()).bind(plan.tenant_id.to_string()).bind(plan.key_id.to_string())
        .fetch_one(&mut *read).await?;
    read.commit().await?;
    let request_locator: String = row.try_get("request_object")?;
    let response_locator: Option<String> = row.try_get("response_object")?;
    let response_locator = response_locator.ok_or("inspected response source is absent")?;
    for (locator, expected) in [
        (&request_locator, &plan.request),
        (&response_locator, &plan.response),
    ] {
        verify_source(&archive, expected).await?;
        verify_source(
            &archive,
            &Source {
                locator: locator.clone(),
                decoded_bytes: expected.decoded_bytes,
                decoded_sha256: expected.decoded_sha256.clone(),
            },
        )
        .await?;
    }
    // Record the actual immutable selection, separately from the SQL fallback.
    let mut selected = serde_json::Map::new();
    for (side, expected, fallback) in [
        ("request", &plan.request, &request_locator),
        ("response", &plan.response, &response_locator),
    ] {
        let root = archive
            .raw_capture_reference(plan.tenant_id, plan.request_id, side)
            .await?;
        if let Some(root) = root {
            verify_source(
                archive,
                &Source {
                    locator: root.object_locator.clone(),
                    decoded_bytes: expected.decoded_bytes,
                    decoded_sha256: expected.decoded_sha256.clone(),
                },
            )
            .await?;
            selected.insert(side.into(), serde_json::json!({
                "selection":"raw_root", "reference":root,
                "reference_blake3":blake3::hash(&serde_json::to_vec(&root)?).to_hex().to_string(),
                "fallback_locator":fallback
            }));
        } else {
            selected.insert(
                side.into(),
                serde_json::json!({
                    "selection":"request_record", "object_locator":fallback,
                    "decoded_bytes":expected.decoded_bytes, "decoded_sha256":expected.decoded_sha256
                }),
            );
        }
    }
    let snapshot: Option<String> = row.try_get("semantic_snapshot_json")?;
    let owner: Option<String> = row.try_get("lease_owner")?;
    let expiry: Option<i64> = row.try_get("lease_expires_at")?;
    let terminal_owner: Option<String> = row.try_get("terminal_lease_owner")?;
    let terminal_expiry: Option<i64> = row.try_get("terminal_lease_expires_at")?;
    let projected: Option<i64> = row.try_get("projected_at")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let ready = projected.is_none()
        && snapshot.as_ref().is_some_and(|value| !value.is_empty())
        && owner
            .as_ref()
            .is_some_and(|value| Uuid::parse_str(value).is_ok())
        && expiry.is_some_and(|value| value <= now)
        && (terminal_owner.is_none() || terminal_expiry.is_some_and(|value| value <= now))
        && row.try_get::<i64, _>("payload_present")? == 0;
    let receipt = serde_json::json!({
        "format_version":1, "kind":"exact_recovery_inspection", "identity":identity,
        "prior_receipt_sha256":format!("{:x}", Sha256::digest(&prior_bytes)),
        "tenant_id":plan.tenant_id, "key_id":plan.key_id, "request_id":plan.request_id,
        "created_at":row.try_get::<i64,_>("created_at")?, "expected_projected_at":projected,
        "expected_owner":owner, "expected_lease_expires_at":expiry,
        "terminal_owner_present":terminal_owner.is_some(), "terminal_lease_expires_at":terminal_expiry,
        "snapshot_sha256":snapshot.as_ref().map(|value| format!("{:x}", Sha256::digest(value.as_bytes()))),
        "request":Source {locator:request_locator, ..plan.request.clone()},
        "response":Source {locator:response_locator, ..plan.response.clone()},
        "selected_sources":selected,
        "sources_verified":true, "ready_for_review":ready,
        "apply_supported":false, "claimed":false, "financial_replay":false,
        "canonical_rebuilt":false, "complete":false
    });
    Ok(receipt)
}

#[cfg(test)]
mod inspection_tests {
    use super::*;

    #[tokio::test]
    async fn exact_inspection_is_read_only_and_changed_sources_do_not_become_ready() {
        let url = std::env::var("MTC_TEST_POSTGRES_URL").unwrap();
        let admin = PgPool::connect(&url).await.unwrap();
        let schema = format!("exact_inspect_{}", Uuid::now_v7().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let mut scoped = url::Url::parse(&url).unwrap();
        scoped
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let pool = PgPool::connect(scoped.as_str()).await.unwrap();
        sqlx::raw_sql("CREATE TABLE conversation_projection_outbox(request_id TEXT PRIMARY KEY, tenant_id TEXT, key_id TEXT, projected_at BIGINT, semantic_snapshot_json TEXT, semantic_payload_snapshot_json TEXT, lease_owner TEXT, lease_expires_at BIGINT, terminal_lease_owner TEXT, terminal_lease_expires_at BIGINT); CREATE TABLE request_record_locators(id TEXT PRIMARY KEY,tenant_id TEXT,key_id TEXT,created_at BIGINT); CREATE TABLE request_records(id TEXT,tenant_id TEXT,key_id TEXT,created_at BIGINT,request_object TEXT,response_object TEXT); CREATE TABLE financial_once(amount BIGINT); INSERT INTO financial_once VALUES(42)")
            .execute(&pool).await.unwrap();
        let archive = ArchiveStore::from_config(&Config::for_test("sqlite::memory:".into()))
            .await
            .unwrap();
        let tenant = Uuid::now_v7();
        let key = Uuid::now_v7();
        let request = Uuid::now_v7();
        let inspected_owner = Uuid::now_v7();
        let source = Bytes::from_static(br#"{"fixture":"original"}"#);
        for side in ["request", "response"] {
            archive
                .put(&format!("inspect/{side}"), source.clone())
                .await
                .unwrap();
        }
        let plan = Plan {
            format_version: 1,
            tenant_id: tenant,
            key_id: key,
            request_id: request,
            expected_projected_at: 42,
            request: Source {
                locator: "inspect/request".into(),
                decoded_bytes: source.len() as u64,
                decoded_sha256: format!("{:x}", Sha256::digest(&source)),
            },
            response: Source {
                locator: "inspect/response".into(),
                decoded_bytes: source.len() as u64,
                decoded_sha256: format!("{:x}", Sha256::digest(&source)),
            },
        };
        sqlx::query("INSERT INTO conversation_projection_outbox VALUES($1,$2,$3,NULL,'{}',NULL,$4,0,NULL,NULL)")
            .bind(request.to_string()).bind(tenant.to_string()).bind(key.to_string()).bind(inspected_owner.to_string()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO request_record_locators VALUES($1,$2,$3,123)")
            .bind(request.to_string())
            .bind(tenant.to_string())
            .bind(key.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO request_records VALUES($1,$2,$3,123,'inspect/request','inspect/response')",
        )
        .bind(request.to_string())
        .bind(tenant.to_string())
        .bind(key.to_string())
        .execute(&pool)
        .await
        .unwrap();
        let before: String =
            sqlx::query_scalar("SELECT to_jsonb(o)::TEXT FROM conversation_projection_outbox o")
                .fetch_one(&pool)
                .await
                .unwrap();
        let report = inspect_verified(&pool, &archive, &plan, "same-plan", b"original receipt")
            .await
            .unwrap();
        assert_eq!(report["ready_for_review"], true);
        assert_eq!(report["expected_owner"], inspected_owner.to_string());
        assert_eq!(report["apply_supported"], false);
        assert_eq!(report["claimed"], false);
        let after: String =
            sqlx::query_scalar("SELECT to_jsonb(o)::TEXT FROM conversation_projection_outbox o")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(before, after);
        sqlx::query(
            "UPDATE conversation_projection_outbox SET lease_expires_at=9223372036854775807",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            inspect_verified(&pool, &archive, &plan, "same-plan", b"original receipt")
                .await
                .unwrap()["ready_for_review"],
            false
        );
        archive
            .put("inspect/response", Bytes::from_static(b"changed"))
            .await
            .unwrap();
        assert!(
            inspect_verified(&pool, &archive, &plan, "same-plan", b"original receipt")
                .await
                .is_err()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT SUM(amount)::BIGINT FROM financial_once")
                .fetch_one(&pool)
                .await
                .unwrap(),
            42
        );
        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}

fn save_inspection_noclobber(path: &std::path::Path, value: &serde_json::Value) -> Result<()> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(temporary.as_file_mut(), value)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path)?;
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod receipt_publication_tests {
    use super::*;
    #[test]
    fn inspection_publication_never_overwrites_a_prior_or_concurrent_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("handover.json");
        let results = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                save_inspection_noclobber(&path, &serde_json::json!({"writer":1})).is_ok()
            });
            let second = scope.spawn(|| {
                save_inspection_noclobber(&path, &serde_json::json!({"writer":2})).is_ok()
            });
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(results.into_iter().filter(|won| *won).count(), 1);
        let original = std::fs::read(&path).unwrap();
        assert!(save_inspection_noclobber(&path, &serde_json::json!({"writer":3})).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[cfg(test)]
#[path = "../conversation-object-tests/exact_recovery_legacy_contract.rs"]
mod legacy_contract;

#[cfg(test)]
mod reviewed_handover_tests {
    use super::*;
    #[test]
    fn review_requires_ready_and_exact_unchanged_evidence() {
        for completed in [false, true] {
            let intent = serde_json::json!({"identity":"same","claim_intent":true,"intent_id":"reviewed","reviewed_handover":{},"canonical_rebuilt":completed,"snapshot":null});
            assert!(reject_reviewed_receipt_in_ordinary_run(&intent).is_err());
        }
        assert!(require_same_plan_bytes(b"original", b"changed").is_err());
        assert!(require_same_plan_bytes(b"original", b"original").is_ok());
        let review = serde_json::json!({"kind":"exact_recovery_inspection","ready_for_review":true,"expected_owner":"original","snapshot_sha256":"same","request":{"locator":"original"}});
        assert!(validate_reviewed_handover(&review, &review).is_ok());
        for field in ["expected_owner", "snapshot_sha256", "request"] {
            let mut changed = review.clone();
            changed[field] = serde_json::Value::Null;
            assert!(validate_reviewed_handover(&review, &changed).is_err());
        }
        let mut completed = review.clone();
        completed["ready_for_review"] = false.into();
        assert!(validate_reviewed_handover(&completed, &completed).is_err());
    }
}
