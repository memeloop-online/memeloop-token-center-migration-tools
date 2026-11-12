//! Bounded read-only evidence for migrated semantic references, never a GC permit.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
struct ObjectIdentity {
    source_target_identity: String,
    training_identity: String,
    tenant_id: String,
    locator: String,
    algorithm: String,
    digest: String,
    bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadbackProgress {
    format_version: u32,
    identity: String,
    training_identity: String,
    ledgers: Vec<PathBuf>,
    audits: Vec<PathBuf>,
    after: Option<ObjectIdentity>,
    objects_read: u64,
    bytes_read: u64,
    rows_proven: u64,
    rows_deferred: u64,
}

struct Candidate {
    audit: ReferenceAudit,
    receipt: PayloadReceipt,
    encoded: Vec<u8>,
    receipt_digest: String,
}

struct Member {
    candidate: Candidate,
    snapshot: SourceVersion,
    semantic: blake3::Hasher,
}

#[derive(Serialize)]
struct RowProof {
    source: SourceVersion,
    stored_version_fingerprint: String,
    copy_receipt_digest: String,
    row_rechecked_at_unix_ms: u128,
}

#[derive(Serialize)]
struct ObjectProof {
    format_version: u32,
    object: ObjectIdentity,
    object_readback_finished_at_unix_ms: u128,
    rows: Vec<RowProof>,
    source_writers_quiesced: bool,
    gc_authorized: bool,
}

fn now_ms() -> Result<u128> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis())
}

fn canonical_directories(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut paths = paths
        .iter()
        .map(std::fs::canonicalize)
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn semantic_hasher(source: &SourceVersion) -> blake3::Hasher {
    let mut digest = blake3::Hasher::new_derive_key("MTC conversation semantic payload v1");
    for value in [
        &source.request_id,
        &source.tenant_id,
        &source.key_id,
        &source.principal_id,
    ] {
        digest.update(&(value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(&(source.encoded_bytes as u64).to_le_bytes());
    digest
}

impl Runner {
    pub(crate) fn readback_semantic_references<'a>(
        &'a self,
        config: &'a Config,
        ledgers: &'a [PathBuf],
        audits: &'a [PathBuf],
        batch: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + 'a>>
    {
        Box::pin(self.readback_semantic_references_inner(config, ledgers, audits, batch))
    }

    async fn readback_semantic_references_inner(
        &self,
        config: &Config,
        ledgers: &[PathBuf],
        audits: &[PathBuf],
        batch: usize,
    ) -> Result<serde_json::Value> {
        if batch == 0 || ledgers.is_empty() || audits.is_empty() {
            return Err("readback requires ledgers, audits and a nonzero operational batch".into());
        }
        let training = training_identity(config)?;
        let ledgers = canonical_directories(ledgers)?;
        let audits = canonical_directories(audits)?;
        let progress_path = self
            .checkpoint
            .with_extension("semantic-readback-progress.json");
        let mut progress = match std::fs::File::open(&progress_path) {
            Ok(file) => serde_json::from_reader::<_, ReadbackProgress>(file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ReadbackProgress {
                format_version: 1,
                identity: self.identity.clone(),
                training_identity: training.clone(),
                ledgers: ledgers.clone(),
                audits: audits.clone(),
                after: None,
                objects_read: 0,
                bytes_read: 0,
                rows_proven: 0,
                rows_deferred: 0,
            },
            Err(error) => return Err(error.into()),
        };
        if progress.format_version != 1
            || progress.identity != self.identity
            || progress.training_identity != training
            || progress.ledgers != ledgers
            || progress.audits != audits
        {
            return Err("semantic readback checkpoint identity mismatch".into());
        }
        // Snapshot only small immutable metadata. Group membership cannot grow
        // during this invocation; later audit publications need a new pass.
        let mut groups: BTreeMap<ObjectIdentity, Vec<Candidate>> = BTreeMap::new();
        let mut seen_audits = BTreeSet::new();
        let mut pending_audits_not_verified = 0_u64;
        let mut audit_rows_deferred = 0_u64;
        for directory in &audits {
            for entry in std::fs::read_dir(directory)? {
                let path = entry?.path();
                if path.extension().and_then(|s| s.to_str()) == Some("pending")
                    && !path.with_extension("json").try_exists()?
                {
                    pending_audits_not_verified += 1;
                }
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                let audit: ReferenceAudit = serde_json::from_reader(std::fs::File::open(&path)?)?;
                if !matches!(
                    audit.status.as_str(),
                    "committed" | "committed_confirmed_by_reread"
                ) {
                    continue;
                }
                if audit.format_version != 1
                    || audit.source_target_identity != self.identity
                    || audit.training_identity != training
                    || audit.source.format_version != 1
                    || path.file_stem().and_then(|s| s.to_str())
                        != Some(audit.copy_receipt_digest.as_str())
                {
                    return Err("semantic readback audit identity mismatch".into());
                }
                // The two committed status spellings prove the same source/ref.
                let encoded_audit = serde_json::to_vec(&(
                    &audit.copy_receipt_digest,
                    &audit.source,
                    &audit.new_reference,
                ))?;
                if !seen_audits.insert(encoded_audit) {
                    continue;
                }
                let mut found = None;
                for ledger in &ledgers {
                    let receipt_path = ledger.join(format!("{}.json", audit.copy_receipt_digest));
                    if receipt_path.try_exists()? {
                        let candidate = self.read_online_receipt(&receipt_path)?;
                        if let Some((_, ref prior, _)) = found {
                            if prior != &candidate.1 {
                                return Err("conflicting immutable copy receipt".into());
                            }
                        }
                        found = Some(candidate);
                    }
                }
                let Some((receipt, encoded, receipt_digest)) = found else {
                    audit_rows_deferred += 1;
                    continue;
                };
                if receipt.field != SourceField::SemanticPayload
                    || receipt.cursor.tenant_id != audit.source.tenant_id
                    || receipt.cursor.content_hash != audit.source.request_id
                    || receipt.source_md5 != audit.source.stored_md5
                    || audit.source.stored_bytes != audit.source.encoded_bytes
                    || u64::try_from(audit.source.encoded_bytes).ok()
                        != Some(receipt.reference.conversation_body_v1.size_bytes)
                    || receipt.reference.chars > receipt.reference.conversation_body_v1.size_bytes
                    || qualified_reference(&receipt, &training)? != audit.new_reference
                {
                    return Err("semantic readback audit/receipt mismatch".into());
                }
                Uuid::parse_str(&audit.source.tenant_id)?;
                Uuid::parse_str(&audit.source.request_id)?;
                let object = &receipt.reference.conversation_body_v1;
                let key = ObjectIdentity {
                    source_target_identity: self.identity.clone(),
                    training_identity: training.clone(),
                    tenant_id: audit.source.tenant_id.clone(),
                    locator: object.object_locator.clone(),
                    algorithm: "blake3".into(),
                    digest: object.blake3_digest.clone(),
                    bytes: object.size_bytes,
                };
                if progress.after.as_ref().is_none_or(|after| &key > after) {
                    groups.entry(key).or_default().push(Candidate {
                        audit,
                        receipt,
                        encoded,
                        receipt_digest,
                    });
                }
            }
        }
        let remaining_groups = groups.len().saturating_sub(batch);
        let proof_directory = self.checkpoint.with_extension("semantic-readback-proofs");
        std::fs::create_dir_all(&proof_directory)?;
        for (object, candidates) in groups.into_iter().take(batch) {
            let mut members = Vec::new();
            let mut current_identities = BTreeSet::new();
            for candidate in candidates {
                let current = source_version(&self.pool, &candidate.receipt.cursor, false).await?;
                let Some(current) = current.filter(|current| {
                    expected_reference(
                        current,
                        &candidate.audit.new_reference,
                        &candidate.audit.source,
                    )
                }) else {
                    progress.rows_deferred += 1;
                    continue;
                };
                // Conflicting proofs of one current row are not resolved by
                // latest-wins. Fail this invocation without publishing a proof.
                if !current_identities
                    .insert((current.tenant_id.clone(), current.request_id.clone()))
                {
                    return Err("conflicting committed audits of a current semantic row".into());
                }
                self.verify_committed_payload_receipt(
                    &candidate.encoded,
                    &candidate.receipt_digest,
                )
                .await?;
                members.push(Member {
                    semantic: semantic_hasher(&current),
                    snapshot: current,
                    candidate,
                });
            }
            if !members.is_empty() {
                let expected_rows = members.len() as u64;
                let proof = self.readback_semantic_group(&object, members).await?;
                progress.rows_deferred += expected_rows - proof.rows.len() as u64;
                progress.rows_proven += proof.rows.len() as u64;
                progress.objects_read += 1;
                progress.bytes_read += object.bytes;
                let key = blake3::hash(&serde_json::to_vec(&proof.object)?)
                    .to_hex()
                    .to_string();
                // Every write follows a new full read. Replaying an interrupted
                // progress update never refreshes timestamps from a cached proof.
                save_checkpoint(&proof_directory.join(format!("{key}.json")), &proof)?;
            }
            progress.after = Some(object);
            save_checkpoint(&progress_path, &progress)?;
        }
        Ok(serde_json::json!({
            "phase":"semantic_reference_readback", "scope":"committed_audit_snapshot", "objects_read":progress.objects_read,
            "bytes_read":progress.bytes_read,"rows_proven":progress.rows_proven,
            "rows_deferred":progress.rows_deferred,"audit_rows_deferred":audit_rows_deferred,
            "pending_audits_not_verified":pending_audits_not_verified,"snapshot_groups_remaining":remaining_groups,
            "later_audits_require_new_pass":true,"source_writers_quiesced":false,
            "global_verified":false,"gc_authorized":false,"source_deleted":false
        }))
    }

    async fn readback_semantic_group(
        &self,
        object: &ObjectIdentity,
        mut members: Vec<Member>,
    ) -> Result<ObjectProof> {
        let first = &members[0].candidate.receipt.reference.conversation_body_v1;
        let mut stream = self
            .target
            .open_tenant_content(Uuid::parse_str(&object.tenant_id)?, first)
            .await?
            .stream;
        let mut body_digest = blake3::Hasher::new();
        let mut bytes = 0_u64;
        let mut chars = 0_u64;
        let mut tail = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .ok_or("readback size overflow")?;
            if bytes > object.bytes {
                return Err("readback object exceeds original bytes".into());
            }
            body_digest.update(&chunk);
            for member in &mut members {
                member.semantic.update(&chunk);
            }
            for part in chunk.chunks(64 * 1024) {
                tail.extend_from_slice(part);
                let valid = match std::str::from_utf8(&tail) {
                    Ok(text) => text.len(),
                    Err(error) if error.error_len().is_none() => error.valid_up_to(),
                    Err(_) => return Err("readback object is not UTF-8".into()),
                };
                chars += std::str::from_utf8(&tail[..valid])?.chars().count() as u64;
                tail.drain(..valid);
            }
        }
        if bytes != object.bytes
            || !tail.is_empty()
            || body_digest.finalize().to_hex().as_str() != object.digest
        {
            return Err("readback object digest/bytes/characters mismatch".into());
        }
        if members
            .iter()
            .any(|member| member.candidate.receipt.reference.chars != chars)
        {
            return Err("readback object character count mismatch".into());
        }
        // Any member's digest failure invalidates the complete object group.
        if members.iter().any(|member| {
            member.semantic.finalize().to_hex().as_str() != member.snapshot.semantic_digest
        }) {
            return Err("readback original semantic digest mismatch".into());
        }
        let finished = now_ms()?;
        let mut rows = Vec::new();
        for member in members {
            let mut tx = self.pool.begin().await?;
            // No S3 operation is inside this short transaction. A lock followed
            // by an exact re-read binds evidence to the current stored version.
            let locked = sqlx::query("SELECT request_id FROM conversation_semantic_payloads WHERE request_id=$1 AND tenant_id=$2 FOR SHARE")
                .bind(&member.snapshot.request_id).bind(&member.snapshot.tenant_id).fetch_optional(&mut *tx).await?;
            if locked.is_none() {
                tx.rollback().await?;
                continue;
            }
            let current = source_version(&mut *tx, &member.candidate.receipt.cursor, false).await?;
            if current.as_ref() != Some(&member.snapshot) {
                tx.rollback().await?;
                continue;
            }
            let rechecked = now_ms()?;
            tx.commit().await?;
            let fingerprint = blake3::hash(&serde_json::to_vec(&member.snapshot)?)
                .to_hex()
                .to_string();
            rows.push(RowProof {
                source: member.snapshot,
                stored_version_fingerprint: fingerprint,
                copy_receipt_digest: member.candidate.receipt_digest,
                row_rechecked_at_unix_ms: rechecked,
            });
        }
        Ok(ObjectProof {
            format_version: 1,
            object: object.clone(),
            object_readback_finished_at_unix_ms: finished,
            rows,
            source_writers_quiesced: false,
            gc_authorized: false,
        })
    }
}
