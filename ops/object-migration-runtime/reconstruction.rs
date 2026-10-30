use super::*;
use memeloop_token_center::archive::{ArchiveWriter, CasArchiveObject};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReconstructionCheckpoint {
    format_version: u32,
    identity: String,
    after: String,
    pub(super) observations: u64,
    pub(super) events: u64,
    pub(super) media: u64,
    pub(super) edges: u64,
    bytes: u64,
    digest: String,
    complete: bool,
    pub(super) verified: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    format_version: u32,
    identity: String,
    observation: String,
    tenant: Uuid,
    events: u64,
    media: u64,
    edges: u64,
    object: CasArchiveObject,
}

struct Output {
    writer: Option<ArchiveWriter>,
    hash: blake3::Hasher,
    bytes: u64,
}

impl Output {
    async fn line(&mut self, value: serde_json::Value) -> Result<()> {
        let mut encoded = serde_json::to_vec(&value)?;
        encoded.push(b'\n');
        self.hash.update(&encoded);
        self.bytes = self
            .bytes
            .checked_add(encoded.len() as u64)
            .ok_or("export size overflow")?;
        if let Some(writer) = &mut self.writer {
            writer.write(Bytes::from(encoded)).await?;
        }
        Ok(())
    }
}

impl Runner {
    pub(super) fn require_reconstruction_receipt(&self) -> Result<()> {
        let receipt: ReconstructionCheckpoint = serde_json::from_reader(std::fs::File::open(
            self.checkpoint.with_extension("reconstruction.json"),
        )?)?;
        if receipt.format_version != 2
            || receipt.identity != self.identity
            || !receipt.complete
            || !receipt.verified
        {
            return Err("verified dialogue reconstruction required before TEST cutover".into());
        }
        Ok(())
    }

    async fn reconstruct_one(&self, observation: &str, copy: bool) -> Result<Receipt> {
        let row = sqlx::query(
            "SELECT c.tenant_id, o.cluster_id, o.request_id, o.leaf_node_hash, row_to_json(o)::TEXT AS metadata
             FROM conversation_observations o JOIN conversation_clusters c ON c.id = o.cluster_id
             WHERE o.id = $1",
        )
        .bind(observation)
        .fetch_one(&self.pool)
        .await?;
        let tenant: String = row.try_get("tenant_id")?;
        let tenant_id = Uuid::parse_str(&tenant)?;
        let cluster: String = row.try_get("cluster_id")?;
        let request: String = row.try_get("request_id")?;
        let mut head: Option<String> = row.try_get("leaf_node_hash")?;
        let metadata: String = row.try_get("metadata")?;
        let staging = format!(
            "migration-staging/conversation-v1/{}/{}",
            self.identity,
            Uuid::now_v7()
        );
        let mut output = Output {
            writer: if copy {
                Some(self.target.start_writer(&staging).await?)
            } else {
                None
            },
            hash: blake3::Hasher::new(),
            bytes: 0,
        };
        let request_object = self.verified_locator("request", &tenant, &request).await?;
        let response_object = self.verified_locator("response", &tenant, &request).await?;
        output.line(serde_json::json!({
            "record":"observation", "format_version":2, "tenant_id":tenant_id,
            "source_metadata":serde_json::from_str::<serde_json::Value>(&metadata)?,
            "raw_request":request_object, "raw_response":response_object,
            "event_order":"descending_ordinal", "fidelity":"historical_projection_with_original_raw"
        })).await?;
        let mut edges = 0_u64;
        let mut after_edge = String::new();
        loop {
            let edge = sqlx::query(
                "SELECT e.id, e.cluster_id, e.from_observation_id, source_cluster.tenant_id AS source_tenant,
                 row_to_json(e)::TEXT AS metadata
                 FROM conversation_edges e
                 LEFT JOIN conversation_observations source ON source.id = e.from_observation_id
                 LEFT JOIN conversation_clusters source_cluster ON source_cluster.id = source.cluster_id
                 WHERE e.to_observation_id = $1 AND e.id > $2 ORDER BY e.id LIMIT 1",
            )
            .bind(observation)
            .bind(&after_edge)
            .fetch_optional(&self.pool)
            .await?;
            let Some(edge) = edge else { break };
            let source: Option<String> = edge.try_get("from_observation_id")?;
            let source_tenant: Option<String> = edge.try_get("source_tenant")?;
            if edge.try_get::<String, _>("cluster_id")? != cluster
                || (source.is_some() && source_tenant.as_deref() != Some(tenant.as_str()))
            {
                return Err("dialogue edge has missing or cross-tenant parent".into());
            }
            let metadata: String = edge.try_get("metadata")?;
            output
                .line(serde_json::json!({
                    "record":"edge",
                    "source_metadata":serde_json::from_str::<serde_json::Value>(&metadata)?
                }))
                .await?;
            after_edge = edge.try_get("id")?;
            edges += 1;
        }
        let mut events = 0_u64;
        let mut media = 0_u64;
        let mut expected_depth = None;
        while let Some(node_hash) = head {
            let node = sqlx::query(
                "SELECT parent_hash, atom_hash, depth FROM context_nodes WHERE tenant_id = $1 AND node_hash = $2",
            ).bind(&tenant).bind(&node_hash).fetch_one(&self.pool).await?;
            let parent: Option<String> = node.try_get("parent_hash")?;
            let atom: String = node.try_get("atom_hash")?;
            let depth: i64 = node.try_get("depth")?;
            if depth < 1
                || expected_depth.is_some_and(|expected| expected != depth)
                || (parent.is_none() != (depth == 1))
                || memeloop_token_center::conversation::digest_parts(parent.as_deref(), &atom)
                    != node_hash
            {
                return Err("dialogue ancestry/order/hash mismatch".into());
            }
            let body = self
                .transfer(&Cursor {
                    tenant_id: tenant.clone(),
                    content_hash: atom.clone(),
                })
                .await?;
            self.target
                .verify_tenant_content(tenant_id, &body.reference.conversation_body_v1)
                .await?;
            output
                .line(serde_json::json!({
                    "record":"event", "ordinal":depth - 1, "node":node_hash,
                    "parent":parent, "atom":atom, "body":body.reference
                }))
                .await?;
            let mut part = -1_i64;
            loop {
                let row = sqlx::query(
                    "SELECT part_index, content_blake3, byte_length, media_type FROM conversation_media_parts
                     WHERE tenant_id = $1 AND turn_id = $2 AND part_index > $3 ORDER BY part_index LIMIT 1",
                ).bind(&tenant).bind(&atom).bind(part).fetch_optional(&self.pool).await?;
                let Some(row) = row else { break };
                part = row.try_get("part_index")?;
                let object = self
                    .verified_locator("media", &tenant, &format!("{atom}:{part}"))
                    .await?;
                if object.blake3_digest != row.try_get::<String, _>("content_blake3")?
                    || object.size_bytes != u64::try_from(row.try_get::<i64, _>("byte_length")?)?
                {
                    return Err("dialogue media reference mismatch".into());
                }
                output
                    .line(serde_json::json!({
                        "record":"media", "ordinal":depth - 1, "part_index":part,
                        "media_type":row.try_get::<String,_>("media_type")?, "object":object
                    }))
                    .await?;
                media += 1;
            }
            events += 1;
            expected_depth = Some(depth - 1);
            head = parent;
        }
        if events == 0 {
            return Err("empty historical dialogue cannot certify reconstruction".into());
        }
        output
            .line(
                serde_json::json!({"record":"end", "events":events, "media":media, "edges":edges}),
            )
            .await?;
        let digest = output.hash.finalize().to_hex().to_string();
        let object = if let Some(writer) = output.writer {
            let staged = writer.finish_staged().await?;
            if staged.blake3_digest != digest || staged.size_bytes != output.bytes {
                return Err("reconstruction write hash mismatch".into());
            }
            let object = self
                .target
                .promote_staged_text_to_cas(tenant_id, &staged)
                .await?;
            self.target.delete(&staged.object_locator).await?;
            object
        } else {
            CasArchiveObject {
                object_locator: format!(
                    "tenants/{tenant_id}/cas/v1/blake3/{}/{digest}",
                    &digest[..2]
                ),
                blake3_digest: digest,
                size_bytes: output.bytes,
            }
        };
        self.target
            .verify_tenant_content(tenant_id, &object)
            .await?;
        Ok(Receipt {
            format_version: 2,
            identity: self.identity.clone(),
            observation: observation.into(),
            tenant: tenant_id,
            events,
            media,
            edges,
            object,
        })
    }

    pub(super) async fn reconstruct_dialogues(
        &self,
        verify: bool,
    ) -> Result<ReconstructionCheckpoint> {
        let atoms = self.load_checkpoint()?;
        if !atoms.verified || atoms.cutover_rows != 0 {
            return Err("independent atom verification before cutover required".into());
        }
        let path = self.checkpoint.with_extension("reconstruction.json");
        let mut checkpoint = match std::fs::File::open(&path) {
            Ok(file) => serde_json::from_reader::<_, ReconstructionCheckpoint>(file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ReconstructionCheckpoint {
                    format_version: 2,
                    identity: self.identity.clone(),
                    ..Default::default()
                }
            }
            Err(error) => return Err(error.into()),
        };
        if checkpoint.format_version != 2 || checkpoint.identity != self.identity {
            return Err("reconstruction checkpoint identity mismatch".into());
        }
        if verify && !checkpoint.complete {
            return Err("completed reconstruction required".into());
        }
        if !verify && checkpoint.complete {
            return Ok(checkpoint);
        }
        if verify {
            checkpoint.verified = false;
            save_checkpoint(&path, &checkpoint)?;
        }
        let mut result = if verify {
            ReconstructionCheckpoint {
                format_version: 2,
                identity: self.identity.clone(),
                ..Default::default()
            }
        } else {
            checkpoint.clone()
        };
        loop {
            let next: Option<String> = sqlx::query_scalar(
                "SELECT id FROM conversation_observations WHERE id > $1 ORDER BY id LIMIT 1",
            )
            .bind(&result.after)
            .fetch_optional(&self.pool)
            .await?;
            let Some(next) = next else { break };
            let receipt = self.reconstruct_one(&next, !verify).await?;
            let key = format!(
                "migration-receipts/conversation-v1/{}/dialogues/{}.json",
                self.identity,
                blake3::hash(next.as_bytes()).to_hex()
            );
            let encoded = serde_json::to_vec(&receipt)?;
            if !verify {
                self.target.put(&key, Bytes::from(encoded.clone())).await?;
            }
            if self.target.get_bounded(&key, 16384).await?.as_ref() != encoded {
                return Err("dialogue reconstruction differs from original receipt".into());
            }
            let mut digest = blake3::Hasher::new();
            digest.update(result.digest.as_bytes());
            digest.update(&encoded);
            result.digest = digest.finalize().to_hex().to_string();
            result.observations += 1;
            result.events += receipt.events;
            result.media += receipt.media;
            result.edges += receipt.edges;
            result.bytes += receipt.object.size_bytes;
            result.after = next;
            if !verify {
                save_checkpoint(&path, &result)?;
            }
        }
        let source_edges: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM conversation_edges")
            .fetch_one(&self.pool)
            .await?;
        if result.edges != u64::try_from(source_edges)? {
            return Err("dialogue edge inventory contains missing target or count mismatch".into());
        }
        if verify {
            if result.observations != checkpoint.observations
                || result.events != checkpoint.events
                || result.media != checkpoint.media
                || result.edges != checkpoint.edges
                || result.bytes != checkpoint.bytes
                || result.digest != checkpoint.digest
            {
                return Err("dialogue reconstruction count/order/media/hash mismatch".into());
            }
            result.verified = true;
        }
        result.complete = true;
        save_checkpoint(&path, &result)?;
        Ok(result)
    }
}
