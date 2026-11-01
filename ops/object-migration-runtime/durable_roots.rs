//! Roots published while SQL is unavailable are authoritative source data too.
//! Every run enumerates from the beginning: object-store list order is not a
//! resumable cursor. CAS publication and exact root creation are idempotent.
use super::*;
use memeloop_token_center::archive::{
    CasArchiveObject, ConversationManifest, ConversationMedia, ConversationPrefix,
    RawResponseAttempt, RawResponseAttemptCapture,
};
use serde::de::DeserializeOwned;
use std::{collections::HashSet, io::Read};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootCheckpoint {
    format_version: u32,
    identity: String,
    source_identity: String,
    pub(super) roots: u64,
    root_bytes: u64,
    pub(super) unique_objects: u64,
    pub(super) decoded_object_bytes: u64,
    pub(super) gap_roots: u64,
    // Sum of domain-separated BLAKE3 rows modulo 2^256, plus exact counts.
    // Independent of backend listing order, without retaining a body/key list.
    digest: [u8; 32],
    complete: bool,
    pub(super) verified: bool,
}

fn add_digest(sum: &mut [u8; 32], value: &[u8]) {
    let hash = blake3::hash(value);
    let mut carry = 0_u16;
    for (output, byte) in sum.iter_mut().zip(hash.as_bytes()) {
        let value = u16::from(*output) + u16::from(*byte) + carry;
        *output = value as u8;
        carry = value >> 8;
    }
}

struct Reader {
    chunks: tokio::sync::mpsc::Receiver<Bytes>,
    current: Bytes,
}
impl Read for Reader {
    fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }
        while self.current.is_empty() {
            match self.chunks.blocking_recv() {
                Some(chunk) => self.current = chunk,
                None => return Ok(0),
            }
        }
        let count = destination.len().min(self.current.len());
        destination[..count].copy_from_slice(&self.current[..count]);
        self.current = self.current.slice(count..);
        Ok(count)
    }
}

async fn json<T: DeserializeOwned + Send + 'static>(
    source: &ArchiveStore,
    tenant: Uuid,
    object: &CasArchiveObject,
) -> Result<T> {
    let mut stream = source.open_tenant_content(tenant, object).await?.stream;
    let (sender, chunks) = tokio::sync::mpsc::channel(2);
    let parsed = tokio::task::spawn_blocking(move || {
        serde_json::from_reader::<_, T>(Reader {
            chunks,
            current: Bytes::new(),
        })
    });
    let pumped: Result<()> = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            for part in chunk.chunks(65536) {
                sender
                    .send(Bytes::copy_from_slice(part))
                    .await
                    .map_err(|_| "durable root JSON parser stopped")?;
            }
        }
        Ok(())
    }
    .await;
    drop(sender);
    let parsed = parsed.await??;
    pumped?;
    Ok(parsed)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    format_version: u32,
    parent: Option<ConversationPrefix>,
    event: CasArchiveObject,
}
#[derive(Deserialize)]
struct EventLinks {
    event_id: String,
    branch_id: String,
    parent_event_id: Option<String>,
    media: Vec<ConversationMedia>,
    gaps: Vec<String>,
    // The arbitrarily long document is consumed by serde's streaming ignored
    // value reader, never accumulated in Value, RawValue or String.
}

struct Walk<'a> {
    runner: &'a Runner,
    source: &'a ArchiveStore,
    verify: bool,
    seen: tempfile::TempDir,
    result: RootCheckpoint,
}
impl Walk<'_> {
    async fn object(&mut self, tenant: Uuid, object: &CasArchiveObject) -> Result<()> {
        // Validate even repeated references, including tenant and exact size.
        let key = blake3::hash(object.object_locator.as_bytes())
            .to_hex()
            .to_string();
        let path = self.seen.path().join(key);
        let encoded = serde_json::to_vec(object)?;
        let mut marker = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if std::fs::read(path)? != encoded {
                    return Err("conflicting repeated CAS reference".into());
                }
                // A previous read verified this exact locator in this run.
                let expected_prefix = format!("tenants/{tenant}/cas/v1/blake3/");
                if !object.object_locator.starts_with(&expected_prefix) {
                    return Err("cross-tenant durable reference".into());
                }
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        marker.write_all(&encoded)?;
        let mut source = self
            .source
            .open_tenant_content(tenant, object)
            .await?
            .stream;
        let staging = format!(
            "migration-staging/conversation-v1/{}/{}",
            self.runner.identity,
            Uuid::now_v7()
        );
        let mut writer = if self.verify {
            None
        } else if object.object_locator.ends_with(".mtcz1") {
            Some(self.runner.target.start_compressed_writer(&staging).await?)
        } else {
            Some(self.runner.target.start_writer(&staging).await?)
        };
        let mut bytes = 0_u64;
        let mut digest = blake3::Hasher::new();
        while let Some(chunk) = source.next().await {
            let chunk = chunk?;
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .ok_or("durable object size overflow")?;
            digest.update(&chunk);
            if let Some(writer) = &mut writer {
                for part in chunk.chunks(65536) {
                    writer.write(Bytes::copy_from_slice(part)).await?;
                }
            }
        }
        if bytes != object.size_bytes || digest.finalize().to_hex().as_str() != object.blake3_digest
        {
            return Err("durable source CAS byte/hash mismatch".into());
        }
        if let Some(writer) = writer {
            let staged = writer.finish_staged().await?;
            let copied = self
                .runner
                .target
                .promote_staged_text_to_cas(tenant, &staged)
                .await?;
            if copied != *object {
                return Err("durable target CAS identity mismatch".into());
            }
            self.runner.target.delete(&staged.object_locator).await?;
        }
        self.runner
            .target
            .verify_tenant_content(tenant, object)
            .await?;
        self.result.unique_objects = self
            .result
            .unique_objects
            .checked_add(1)
            .ok_or("object count overflow")?;
        self.result.decoded_object_bytes = self
            .result
            .decoded_object_bytes
            .checked_add(bytes)
            .ok_or("object byte count overflow")?;
        add_digest(
            &mut self.result.digest,
            &serde_json::to_vec(&("cas", tenant, object))?,
        );
        Ok(())
    }

    async fn conversation(&mut self, tenant: Uuid, manifest: CasArchiveObject) -> Result<bool> {
        self.object(tenant, &manifest).await?;
        let manifest: ConversationManifest = json(self.source, tenant, &manifest).await?;
        if manifest.format_version != 1
            || manifest.tenant_id != tenant
            || manifest.session_id.is_empty()
            || manifest.branch_id.is_empty()
            || manifest.parent_event_id.is_some() != manifest.parent_branch_id.is_some()
        {
            return Err("invalid durable conversation manifest".into());
        }
        let mut gap = !manifest.gaps.is_empty() || manifest.head.is_none();
        for capture in &manifest.raw_captures {
            if !matches!(capture.side.as_str(), "request" | "response")
                || capture.request_id.is_empty()
            {
                return Err("invalid durable original capture".into());
            }
            self.object(tenant, &capture.object).await?;
        }
        let mut cursor = manifest.head.clone();
        let mut remaining = cursor.as_ref().map_or(0, |head| head.event_count);
        let mut ids = HashSet::new();
        let mut parents = HashSet::new();
        let mut branch_parent_found = manifest.parent_event_id.is_none();
        let mut first = true;
        while let Some(head) = cursor {
            if remaining == 0 || head.event_count != remaining {
                return Err("durable prefix count/order mismatch".into());
            }
            self.object(tenant, &head.object).await?;
            let node: Node = json(self.source, tenant, &head.object).await?;
            if node.format_version != 1 {
                return Err("invalid durable prefix version".into());
            }
            self.object(tenant, &node.event).await?;
            let event: EventLinks = json(self.source, tenant, &node.event).await?;
            if event.event_id.is_empty()
                || event.branch_id.is_empty()
                || (first && event.branch_id != manifest.branch_id)
            {
                return Err("durable event/branch mismatch".into());
            }
            first = false;
            gap |= !event.gaps.is_empty();
            if manifest.parent_event_id.as_ref() == Some(&event.event_id)
                && manifest.parent_branch_id.as_ref() == Some(&event.branch_id)
            {
                branch_parent_found = true;
            }
            parents.remove(&event.event_id);
            if !ids.insert(event.event_id) {
                return Err("duplicate durable event identity".into());
            }
            if let Some(parent) = event.parent_event_id {
                if ids.contains(&parent) {
                    return Err("durable event parent order mismatch".into());
                }
                parents.insert(parent);
            }
            for media in event.media {
                self.object(tenant, &media.object).await?;
            }
            remaining -= 1;
            cursor = node.parent;
        }
        if remaining != 0 || !parents.is_empty() || !branch_parent_found {
            return Err("incomplete durable event ancestry".into());
        }
        Ok(gap)
    }

    async fn root(&mut self, key: &str) -> Result<()> {
        let segments = key.split('/').collect::<Vec<_>>();
        if segments.len() < 6 || segments[0] != "tenants" || segments[3] != "v1" {
            return Err("unknown durable root shape".into());
        }
        let tenant = Uuid::parse_str(segments[1])?;
        // Each root is a small reference/envelope, never a conversation body.
        let encoded = self.source.get_bounded(key, 4096).await?;
        let gap = match (segments[2], &segments[4..]) {
            ("raw", [request, "request.json" | "response.json"]) => {
                Uuid::parse_str(request)?;
                self.object(
                    tenant,
                    &serde_json::from_slice::<CasArchiveObject>(&encoded)?,
                )
                .await?;
                false
            }
            ("raw", [request, "supplier-summary.json"]) => {
                Uuid::parse_str(request)?;
                let summary = std::str::from_utf8(&encoded)?;
                if memeloop_token_center::supplier_error::supplier_error_from_inline_json(Some(
                    summary,
                ))
                .is_none()
                {
                    return Err("invalid durable supplier summary".into());
                }
                false
            }
            (
                "raw",
                [
                    request,
                    side @ ("request.json.failed" | "response.json.failed"),
                ],
            ) => {
                let request = Uuid::parse_str(request)?;
                let marker: serde_json::Value = serde_json::from_slice(&encoded)?;
                if marker["format_version"] != 1 || marker["reason"] != "capture_failed" {
                    return Err("invalid durable capture failure evidence".into());
                }
                self.source
                    .raw_capture_reference(
                        tenant,
                        request,
                        if *side == "request.json.failed" {
                            "request"
                        } else {
                            "response"
                        },
                    )
                    .await?
                    .is_none()
            }
            ("raw", [request, "attempts", ordinal, "response.json"]) => {
                Uuid::parse_str(request)?;
                let ordinal: usize = ordinal.parse()?;
                let capture: RawResponseAttemptCapture = serde_json::from_slice(&encoded)?;
                if ordinal == 0
                    || capture.format_version != 1
                    || capture.attempt.outbound_attempt != ordinal
                {
                    return Err("invalid durable outbound attempt".into());
                }
                self.object(tenant, &capture.response).await?;
                false
            }
            ("raw", [request, "attempts", ordinal, "response.json.failed"]) => {
                let request = Uuid::parse_str(request)?;
                let ordinal: usize = ordinal.parse()?;
                let attempt: RawResponseAttempt = serde_json::from_slice(&encoded)?;
                if ordinal == 0 || attempt.outbound_attempt != ordinal {
                    return Err("invalid durable attempt failure evidence".into());
                }
                self.source
                    .response_attempt(tenant, request, ordinal)
                    .await?
                    .is_none()
            }
            ("conversations", ["requests", request]) => {
                Uuid::parse_str(
                    request
                        .strip_suffix(".json")
                        .ok_or("invalid conversation root name")?,
                )?;
                self.conversation(tenant, serde_json::from_slice(&encoded)?)
                    .await?
            }
            _ => {
                return Err(
                    "unknown durable root type; source retained and verification refused".into(),
                );
            }
        };
        let receipt_key = format!(
            "migration-receipts/conversation-v1/{}/roots/{}.json",
            self.runner.identity,
            blake3::hash(key.as_bytes()).to_hex()
        );
        let receipt = serde_json::json!({"format_version":1,"identity":self.runner.identity,"source_identity":self.result.source_identity,"root":key,"bytes":encoded.len(),"blake3":blake3::hash(&encoded).to_hex().to_string(),"gap":gap});
        if self.verify {
            if self.runner.target.get_bounded(key, 4096).await? != encoded {
                return Err("durable target root bytes differ".into());
            }
            let prior: serde_json::Value =
                serde_json::from_slice(&self.runner.target.get_bounded(&receipt_key, 8192).await?)?;
            if prior != receipt {
                return Err("durable root receipt/source mismatch".into());
            }
        } else {
            self.runner
                .target
                .restore_durable_root(key, encoded.clone())
                .await?;
            if self.runner.target.get_bounded(key, 4096).await? != encoded {
                return Err("durable target root readback mismatch".into());
            }
            self.runner
                .target
                .put(&receipt_key, Bytes::from(serde_json::to_vec(&receipt)?))
                .await?;
        }
        self.result.roots = self
            .result
            .roots
            .checked_add(1)
            .ok_or("root count overflow")?;
        self.result.root_bytes = self
            .result
            .root_bytes
            .checked_add(encoded.len() as u64)
            .ok_or("root byte count overflow")?;
        self.result.gap_roots = self
            .result
            .gap_roots
            .checked_add(u64::from(gap))
            .ok_or("gap count overflow")?;
        add_digest(
            &mut self.result.digest,
            &serde_json::to_vec(&("root", key, &receipt))?,
        );
        Ok(())
    }
}

impl Runner {
    pub(super) async fn transfer_durable_roots(
        &self,
        source: &ArchiveStore,
        source_identity: &str,
        verify: bool,
    ) -> Result<RootCheckpoint> {
        let path = self.checkpoint.with_extension("roots.json");
        let baseline: Option<RootCheckpoint> = if verify {
            Some(serde_json::from_reader(std::fs::File::open(&path)?)?)
        } else {
            None
        };
        let result = RootCheckpoint {
            format_version: 1,
            identity: self.identity.clone(),
            source_identity: source_identity.to_owned(),
            ..Default::default()
        };
        // Revoke old authority before listing, opening a reference or copying.
        save_checkpoint(&path, &result)?;
        if let Some(prior) = &baseline
            && (prior.format_version != 1
                || prior.identity != self.identity
                || prior.source_identity != source_identity
                || !prior.complete)
        {
            return Err("complete matching durable root copy required".into());
        }
        let parent = self
            .checkpoint
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let mut walk = Walk {
            runner: self,
            source,
            verify,
            seen: tempfile::TempDir::new_in(parent)?,
            result,
        };
        let roots = source.durable_roots();
        tokio::pin!(roots);
        while let Some(key) = roots.next().await {
            walk.root(&key?).await?;
            save_checkpoint(&path, &walk.result)?;
        }
        walk.result.complete = true;
        if let Some(mut prior) = baseline {
            prior.verified = false;
            if prior != walk.result {
                return Err("durable source root/object inventory changed since copy".into());
            }
            walk.result.verified = walk.result.gap_roots == 0;
        }
        save_checkpoint(&path, &walk.result)?;
        if verify && !walk.result.verified {
            return Err("durable roots retain explicit historical gaps".into());
        }
        Ok(walk.result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unindexed_roots_copy_exact_graph_attempts_media_and_large_compressed_originals() {
        let source = ArchiveStore::from_config(&Config::for_test("sqlite::memory:".into()))
            .await
            .unwrap();
        let mut config = Config::for_test("sqlite::memory:".into());
        if let Ok(endpoint) = std::env::var("MTC_RUSTFS_TEST_ENDPOINT") {
            config.archive_backend = memeloop_token_center::config::ArchiveBackend::S3;
            config.s3_endpoint = Some(endpoint);
            config.s3_bucket = Some(std::env::var("MTC_RUSTFS_TEST_BUCKET").unwrap());
            config.s3_access_key = Some(std::env::var("MTC_RUSTFS_TEST_ACCESS_KEY").unwrap());
            config.s3_secret_key = Some(std::env::var("MTC_RUSTFS_TEST_SECRET_KEY").unwrap());
            config.s3_allow_http = true;
        }
        let directory = tempfile::tempdir().unwrap();
        // No source SQL record exists for any of these roots. This lazy pool
        // cannot satisfy an accidental SQL-backed inventory implementation.
        let runner = Runner {
            pool: PgPoolOptions::new()
                .connect_lazy("postgres://fixture@127.0.0.1:1/unused_test")
                .unwrap(),
            source: Some(source.clone()),
            target: ArchiveStore::from_config(&config).await.unwrap(),
            checkpoint: directory.path().join("roots-fixture.json"),
            identity: Uuid::now_v7().to_string(),
        };
        let tenant = Uuid::now_v7();
        let request = Uuid::now_v7();
        let document = serde_json::json!({"messages":[
            {"role":"user","content":[{"type":"text","text":"工具😀".repeat(50000)}, {"type":"image_url","image_url":{"url":"data:image/png;base64,AQIDBA=="}}]},
            {"role":"assistant","tool_calls":[{"id":"call-root","type":"function","function":{"name":"search","arguments":"{\"query\":\"root\"}"}}]},
            {"role":"tool","tool_call_id":"call-root","content":"retained exact tool output"}
        ]});
        let request_bytes = Bytes::from(serde_json::to_vec(&document).unwrap());
        let response = Bytes::from_static(
            br#"{"choices":[{"message":{"role":"assistant","content":"exact final answer"}}]}"#,
        );
        let hints = memeloop_token_center::conversation::ConversationHints {
            session_id: Some(format!("unindexed-session{}", "x".repeat(1024 * 1024))),
            branch_id: Some("unindexed-branch".into()),
            ..Default::default()
        };
        let manifest = source
            .capture_conversation_documents(
                tenant,
                request,
                &hints,
                request_bytes.clone(),
                Some(response.clone()),
                true,
            )
            .await
            .unwrap();
        assert!(
            manifest.size_bytes > 1024 * 1024,
            "manifest metadata has no aggregate 1 MiB ceiling"
        );
        source
            .publish_request_conversation(tenant, request, &manifest)
            .await
            .unwrap();
        let attempt = RawResponseAttempt {
            outbound_attempt: 1,
            upstream_account_id: Uuid::now_v7(),
            model_route_id: Uuid::now_v7(),
            status_code: 429,
        };
        let rejection = Bytes::from_static(b"original 429, before candidate failover\r\n");
        let rejection_object = source
            .put_tenant_content(tenant, rejection.clone())
            .await
            .unwrap();
        source
            .publish_response_attempt(tenant, request, attempt, &rejection_object)
            .await
            .unwrap();
        let unrelated = source
            .put_tenant_content(
                tenant,
                Bytes::from_static(b"unreferenced CAS must not be copied"),
            )
            .await
            .unwrap();
        source
            .put(
                "staging/proxy/unreferenced-root-test/body",
                Bytes::from_static(b"raw FIFO cache"),
            )
            .await
            .unwrap();
        let large_request = Uuid::now_v7();
        let mut writer = source
            .start_compressed_writer(&format!("fixture-roots/{large_request}"))
            .await
            .unwrap();
        let chunk = Bytes::from(vec![b'R'; 65536]);
        let mut digest = blake3::Hasher::new();
        for _ in 0..(130 * 1024 * 1024 / 65536) {
            writer.write(chunk.clone()).await.unwrap();
            digest.update(&chunk);
        }
        let staged = writer.finish_staged().await.unwrap();
        let large = source
            .promote_staged_text_to_cas(tenant, &staged)
            .await
            .unwrap();
        source
            .publish_raw_capture(tenant, large_request, "response", &large)
            .await
            .unwrap();
        assert_eq!(large.blake3_digest, digest.finalize().to_hex().to_string());
        let copied = runner
            .transfer_durable_roots(&source, "explicit-source-fixture", false)
            .await
            .unwrap();
        assert_eq!(copied.roots, 5);
        assert!(copied.unique_objects > 5);
        assert!(copied.decoded_object_bytes > 130 * 1024 * 1024);
        let verified = runner
            .transfer_durable_roots(&source, "explicit-source-fixture", true)
            .await
            .unwrap();
        assert!(verified.verified);
        assert_eq!(verified.unique_objects, copied.unique_objects);
        assert_eq!(verified.digest, copied.digest);
        assert_eq!(
            runner
                .transfer_durable_roots(&source, "explicit-source-fixture", false)
                .await
                .unwrap()
                .digest,
            copied.digest
        );
        assert!(
            runner
                .transfer_durable_roots(&source, "explicit-source-fixture", true)
                .await
                .unwrap()
                .verified
        );
        let copied_attempt = runner
            .target
            .response_attempt(tenant, request, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(copied_attempt.attempt, attempt);
        assert_eq!(
            runner
                .target
                .get_tenant_content(tenant, &copied_attempt.response, rejection.len())
                .await
                .unwrap(),
            rejection
        );
        assert_eq!(
            runner
                .target
                .get_tenant_content(
                    tenant,
                    &runner
                        .target
                        .raw_capture_reference(tenant, request, "request")
                        .await
                        .unwrap()
                        .unwrap(),
                    request_bytes.len()
                )
                .await
                .unwrap(),
            request_bytes
        );
        assert!(
            runner
                .target
                .verify_tenant_content(tenant, &unrelated)
                .await
                .is_err()
        );
        assert!(
            runner
                .target
                .head_size("staging/proxy/unreferenced-root-test/body")
                .await
                .is_err()
        );
        assert_eq!(
            source
                .get("staging/proxy/unreferenced-root-test/body")
                .await
                .unwrap(),
            "raw FIFO cache"
        );
        assert_eq!(
            runner
                .target
                .request_conversation_reference(tenant, request)
                .await
                .unwrap(),
            manifest
        );
        let mut exported = runner
            .target
            .stream_conversation_export(tenant, &manifest)
            .await
            .unwrap();
        let mut events = 0;
        let mut ended = false;
        while let Some(line) = exported.next().await {
            let record: serde_json::Value = serde_json::from_slice(&line.unwrap()).unwrap();
            if record["record"] == "event" {
                events += 1;
                assert_eq!(record["branch_id"], "unindexed-branch");
                let object: CasArchiveObject =
                    serde_json::from_value(record["object"].clone()).unwrap();
                let actual: serde_json::Value = serde_json::from_slice(
                    &runner
                        .target
                        .get_tenant_content(tenant, &object, object.size_bytes as usize)
                        .await
                        .unwrap(),
                )
                .unwrap();
                if actual["kind"] == "messages" && actual["document"]["role"] == "tool" {
                    assert_eq!(actual["document"]["tool_call_id"], "call-root");
                }
            }
            if record["record"] == "end" {
                assert_eq!(record["verified"], true);
                ended = true;
            }
        }
        assert!(events >= 5 && ended);
        // An added missing original revokes prior verification. Its marker is
        // copied exactly and can only be healed by real source bytes/root.
        let missing = Uuid::now_v7();
        source
            .publish_raw_capture_failure(tenant, missing, "request")
            .await
            .unwrap();
        assert!(
            runner
                .transfer_durable_roots(&source, "explicit-source-fixture", true)
                .await
                .is_err()
        );
        let invalidated: RootCheckpoint = serde_json::from_reader(
            std::fs::File::open(runner.checkpoint.with_extension("roots.json")).unwrap(),
        )
        .unwrap();
        assert!(!invalidated.verified);
        let gap_copy = runner
            .transfer_durable_roots(&source, "explicit-source-fixture", false)
            .await
            .unwrap();
        assert_eq!(gap_copy.gap_roots, 1);
        assert!(
            runner
                .transfer_durable_roots(&source, "explicit-source-fixture", true)
                .await
                .is_err()
        );
        assert!(
            runner
                .target
                .raw_capture_failed(tenant, missing, "request")
                .await
                .unwrap()
        );
        let recovered = source
            .put_tenant_content(tenant, Bytes::from_static(b"actual recovered request"))
            .await
            .unwrap();
        source
            .publish_raw_capture(tenant, missing, "request", &recovered)
            .await
            .unwrap();
        assert_eq!(
            runner
                .transfer_durable_roots(&source, "explicit-source-fixture", false)
                .await
                .unwrap()
                .gap_roots,
            0
        );
        assert!(
            runner
                .transfer_durable_roots(&source, "explicit-source-fixture", true)
                .await
                .unwrap()
                .verified
        );
        source.verify_tenant_content(tenant, &large).await.unwrap();
        source
            .verify_tenant_content(tenant, &manifest)
            .await
            .unwrap();
        // Source/target ownership cannot be changed by reusing a checkpoint.
        assert!(
            runner
                .transfer_durable_roots(&source, "different-source", true)
                .await
                .is_err()
        );
    }
}
