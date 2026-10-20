use super::*;

struct ActiveSummary {
    session_id: String,
    remaining: i64,
    expected_digest: String,
    digest: Sha256,
}

pub(super) struct StableProjectionValidator<'a> {
    manifest: &'a StableDeltaManifest,
    active: Option<ActiveSummary>,
    previous_session_id: Option<String>,
    set_digest: Sha256,
    first_summary: bool,
    summaries: i64,
    requests: i64,
    tombstones: i64,
}

#[derive(Serialize)]
pub(super) struct PresentDigestSummary<'a> {
    pub(super) first_at: &'a str,
    pub(super) last_at: &'a str,
    pub(super) records_sha256: &'a str,
    pub(super) requests: i64,
    pub(super) session_id: &'a str,
}

#[derive(Serialize)]
pub(super) struct TombstoneDigestSummary<'a> {
    pub(super) last_at: &'a str,
    pub(super) requests: i64,
    pub(super) session_id: &'a str,
    pub(super) deleted: bool,
    pub(super) deleted_at: &'a str,
}

impl<'a> StableProjectionValidator<'a> {
    pub(super) fn new(
        manifest: &'a StableDeltaManifest,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if manifest.snapshot_schema_version != 2 {
            return Err("stable projection controls require snapshot schema v2".into());
        }
        let mut set_digest = Sha256::new();
        set_digest.update(b"[");
        Ok(Self {
            manifest,
            active: None,
            previous_session_id: None,
            set_digest,
            first_summary: true,
            summaries: 0,
            requests: 0,
            tombstones: 0,
        })
    }

    fn finish_active(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(active) = self.active.take()
            && (active.remaining != 0
                || format!("{:x}", active.digest.finalize()) != active.expected_digest)
        {
            return Err(
                "stable session record count or records_sha256 disagrees with its summary".into(),
            );
        }
        Ok(())
    }

    pub(super) fn observe_summary(
        &mut self,
        summary: &SessionSummaryControl,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.finish_active()?;
        if self
            .previous_session_id
            .as_deref()
            .is_some_and(|previous| previous.as_bytes() >= summary.session_id.as_bytes())
        {
            return Err("stable session summaries are duplicated or not bytewise ordered".into());
        }
        self.previous_session_id = Some(summary.session_id.clone());
        if !self.first_summary {
            self.set_digest.update(b",");
        }
        self.first_summary = false;
        self.summaries += 1;
        self.requests = self
            .requests
            .checked_add(summary.requests)
            .ok_or("stable summary request count overflow")?;
        if summary.deleted {
            self.tombstones += 1;
            let last = summary
                .last_at
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            let deleted = summary
                .deleted_at
                .expect("validated tombstone time")
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            self.set_digest
                .update(serde_json::to_vec(&TombstoneDigestSummary {
                    last_at: &last,
                    requests: 0,
                    session_id: &summary.session_id,
                    deleted: true,
                    deleted_at: &deleted,
                })?);
        } else {
            let first = summary
                .first_at
                .expect("validated present time")
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            let last = summary
                .last_at
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            let records_sha256 = summary
                .records_sha256
                .as_deref()
                .expect("validated present digest");
            self.set_digest
                .update(serde_json::to_vec(&PresentDigestSummary {
                    first_at: &first,
                    last_at: &last,
                    records_sha256,
                    requests: summary.requests,
                    session_id: &summary.session_id,
                })?);
            self.active = Some(ActiveSummary {
                session_id: summary.session_id.clone(),
                remaining: summary.requests,
                expected_digest: records_sha256.to_owned(),
                digest: Sha256::new(),
            });
        }
        Ok(())
    }

    pub(super) fn observe_record(
        &mut self,
        record: &ArchiveRecord,
        raw_line: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let active = self
            .active
            .as_mut()
            .ok_or("stable snapshot record is missing its present summary")?;
        if active.remaining <= 0 || active.session_id != record.session_id {
            return Err("stable snapshot record is foreign to its active summary".into());
        }
        active.digest.update(raw_line);
        active.remaining -= 1;
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.finish_active()?;
        self.set_digest.update(b"]");
        let digest = format!("{:x}", self.set_digest.finalize());
        if digest != self.manifest.session_set_sha256
            || self.summaries != self.manifest.session_count
            || self.requests != self.manifest.request_count
            || self.tombstones != self.manifest.deleted_session_count
        {
            return Err("stable snapshot set digest or audit counts disagree with its complete summary projection".into());
        }
        Ok(())
    }
}

pub(super) fn parse_archive_line(
    line: &[u8],
) -> Result<Option<ParsedArchiveLine>, Box<dyn std::error::Error + Send + Sync>> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let envelope: Value = serde_json::from_slice(line)?;
    if envelope.get("_mtc_delta_type").is_some() {
        let summary: SessionSummaryControl = serde_json::from_value(envelope)?;
        let digest_valid = summary.records_sha256.as_deref().is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
        let shape_valid = if summary.deleted {
            summary.requests == 0
                && summary.first_at.is_none()
                && summary.records_sha256.is_none()
                && summary.deleted_at == Some(summary.last_at)
        } else {
            summary.requests > 0
                && summary
                    .first_at
                    .is_some_and(|first| first <= summary.last_at)
                && digest_valid
                && summary.deleted_at.is_none()
        };
        if summary.delta_type != "session_summary"
            || summary.schema_version != 2
            || !shape_valid
            || summary.session_id.is_empty()
            || summary.session_id.len() > 512
            || summary
                .session_id
                .bytes()
                .any(|byte| !(0x20..=0x7e).contains(&byte))
        {
            return Err("archive delta contains an invalid stable session summary".into());
        }
        return Ok(Some(ParsedArchiveLine::Summary(summary)));
    }
    let record: ArchiveRecord = serde_json::from_value(envelope)?;
    if !matches!(record.schema_version, 1 | 2) {
        return Err(format!(
            "unsupported cpa-session-archive schema {}",
            record.schema_version
        )
        .into());
    }
    if record.request_id.is_empty()
        || record.request_id.len() > 512
        || record.request_id.chars().any(char::is_control)
        || record.session_id.len() > 1024
        || record.session_id.chars().any(char::is_control)
        || record.completed_at < record.started_at
    {
        return Err("archive record contains an invalid identity or time range".into());
    }
    let mut canonical_hasher = blake3::Hasher::new();
    serde_json::to_writer(&mut canonical_hasher, &record)?;
    let record_digest = canonical_hasher.finalize().to_hex().to_string();
    Ok(Some(ParsedArchiveLine::Record(
        Box::new(record),
        record_digest,
    )))
}

#[cfg(test)]
pub(super) fn parse_record(
    line: &[u8],
) -> Result<Option<(ArchiveRecord, String)>, Box<dyn std::error::Error + Send + Sync>> {
    match parse_archive_line(line)? {
        None => Ok(None),
        Some(ParsedArchiveLine::Record(record, digest)) => Ok(Some((*record, digest))),
        Some(ParsedArchiveLine::Summary(_)) => Err("expected an archive record".into()),
    }
}

pub(super) fn archive_record_inside_overlap(record: &ArchiveRecord, lower_bound: i64) -> bool {
    let started_at = record.started_at.timestamp_millis();
    let completed_at = record.completed_at.timestamp_millis();
    // This exactly mirrors the source delta cursor: long-running or late-completed
    // records remain eligible when either endpoint is inside the overlap window.
    started_at >= lower_bound || completed_at >= lower_bound
}

pub(super) fn archived_credential_hash(record: &ArchiveRecord) -> Result<Option<String>, AppError> {
    let candidate = match record.schema_version {
        // Schema 1 defines key_id itself as the legacy bare digest.  Do not
        // broaden that older envelope by interpreting labels or prefixes.
        1 => nonempty(&record.key_id),
        2 => match nonempty(&record.credential_hash) {
            // An explicit schema-2 field is authoritative: malformed data must
            // not fall back to key_id.  Only the specified sha256 prefix is
            // stripped, and the digest is canonicalized for proof stability.
            Some(value) => {
                return normalize_schema_v2_sha256(value).map(Some).ok_or_else(|| {
                    AppError::BadRequest("archive credential hash is malformed".into())
                });
            }
            None => nonempty(&record.key_id),
        },
        _ => None,
    };
    candidate
        .map(|value| {
            normalize_bare_sha256(value)
                .ok_or_else(|| AppError::BadRequest("archive credential hash is malformed".into()))
        })
        .transpose()
}

pub(super) fn normalize_bare_sha256(value: &str) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

pub(super) fn normalize_schema_v2_sha256(value: &str) -> Option<String> {
    normalize_bare_sha256(value.strip_prefix("sha256:").unwrap_or(value))
}

pub(super) fn payload_bytes(value: &Value) -> Result<Option<Vec<u8>>, serde_json::Error> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.as_bytes().to_vec())),
        value => serde_json::to_vec(value).map(Some),
    }
}

pub(super) fn structured_request(value: &Value) -> Option<&Value> {
    match value {
        Value::Array(_) | Value::Object(_) => Some(value),
        _ => None,
    }
}

pub(super) fn conversation_hints(record: &ArchiveRecord) -> ConversationHints {
    let turn_id = first_facet(record, "turn.id").map(str::to_owned);
    let parent_turn_id = first_facet(record, "parent.turn.id")
        .or_else(|| metadata_string(record, "parent_response_id"))
        .map(str::to_owned);
    let branch_id = first_facet(record, "branch.id").map(str::to_owned);
    let compaction = record
        .facets
        .get("request.kind")
        .is_some_and(|values| values.iter().any(|value| value.contains("compaction")));
    // Archive envelopes have no trusted transport header. Accept only the
    // typed metadata marker, and only when the archive also names a parent.
    let subagent = parent_turn_id.is_some()
        && record
            .metadata
            .get("subagent")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    ConversationHints {
        session_id: nonempty(&record.session_id).map(str::to_owned),
        turn_id,
        parent_turn_id,
        branch_id,
        compaction,
        subagent,
        session_name: metadata_string(record, "session_name").and_then(safe_execution_metadata),
        trace_id: metadata_string(record, "trace_id").and_then(safe_execution_metadata),
        span_id: metadata_string(record, "span_id").and_then(safe_execution_metadata),
        parent_span_id: metadata_string(record, "parent_span_id").and_then(safe_execution_metadata),
        agent_id: metadata_string(record, "agent_id").and_then(safe_execution_metadata),
        parent_agent_id: metadata_string(record, "parent_agent_id")
            .and_then(safe_execution_metadata),
        task_kind: metadata_string(record, "task_kind").and_then(safe_execution_metadata),
        labels: archive_execution_labels(record),
    }
}

fn safe_execution_metadata(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_owned())
    }
}

fn archive_execution_labels(record: &ArchiveRecord) -> std::collections::BTreeMap<String, String> {
    record
        .metadata
        .get("session_labels")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|labels| labels.iter())
        .filter_map(|(key, value)| {
            let normalized = key.to_ascii_lowercase().replace('-', "_");
            let secret_like = [
                "authorization",
                "bearer",
                "cookie",
                "credential",
                "password",
                "private",
                "secret",
                "token",
                "api_key",
            ]
            .iter()
            .any(|needle| normalized.contains(needle));
            if key.is_empty()
                || key.len() > 64
                || secret_like
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                return None;
            }
            let value = value.as_str()?.trim();
            if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                return None;
            }
            Some((key.clone(), value.to_owned()))
        })
        .take(16)
        .collect()
}

pub(super) fn first_facet<'a>(record: &'a ArchiveRecord, name: &str) -> Option<&'a str> {
    record
        .facets
        .get(name)
        .and_then(|values| values.iter().find_map(|value| nonempty(value)))
}

pub(super) fn metadata_string<'a>(record: &'a ArchiveRecord, name: &str) -> Option<&'a str> {
    record
        .metadata
        .get(name)
        .and_then(Value::as_str)
        .and_then(nonempty)
}

pub(super) fn archive_protocol(record: &ArchiveRecord) -> String {
    nonempty(&record.request_path)
        .or_else(|| first_facet(record, "request.path"))
        .or_else(|| metadata_string(record, "request_path"))
        .or_else(|| first_facet(record, "client"))
        .unwrap_or("session-archive")
        .to_owned()
}

pub(super) fn archive_usage(record: &ArchiveRecord) -> (i64, i64) {
    let usage = record
        .response
        .pointer("/response/usage")
        .or_else(|| record.response.pointer("/usage"));
    let Some(usage) = usage else {
        return (0, 0);
    };
    let Some(input_tokens) = usage.get("input_tokens").and_then(Value::as_i64) else {
        return (0, 0);
    };
    let Some(output_tokens) = usage.get("output_tokens").and_then(Value::as_i64) else {
        return (0, 0);
    };
    if input_tokens < 0 || output_tokens < 0 {
        (0, 0)
    } else {
        (input_tokens, output_tokens)
    }
}

pub(super) fn archive_error_code(record: &ArchiveRecord) -> Option<String> {
    let outcome = record.outcome.trim();
    let successful =
        outcome.eq_ignore_ascii_case("success") || outcome.eq_ignore_ascii_case("succeeded");
    if successful && record.status_code < 400 {
        return None;
    }
    if !outcome.is_empty() && !successful {
        let normalized: String = outcome
            .chars()
            .take(200)
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-') {
                    character.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        return nonempty(&normalized).map(str::to_owned);
    }
    (record.status_code >= 400).then(|| format!("http_{}", record.status_code))
}

pub(super) fn nonempty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

pub(super) fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub(super) fn validate_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 200
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(format!("{label} contains unsupported characters"));
    }
    Ok(())
}

pub(super) async fn read_bounded_line(
    reader: &mut BufReader<tokio::fs::File>,
    maximum: usize,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(take) > maximum {
            return Err(format!("archive JSONL record exceeds {maximum} bytes").into());
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.last() == Some(&b'\n') {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(metadata: Value, facets: Value) -> ArchiveRecord {
        serde_json::from_value(json!({
            "schema_version": 2,
            "session_id": "archive-session",
            "request_id": "archive-request",
            "started_at": "2026-08-22T00:00:00Z",
            "completed_at": "2026-08-22T00:00:01Z",
            "metadata": metadata,
            "facets": facets
        }))
        .expect("archive record")
    }

    #[test]
    fn archive_subagent_marker_requires_a_typed_marker_and_explicit_parent() {
        let linked = conversation_hints(&record(
            json!({"subagent": true, "parent_response_id": "parent-response"}),
            json!({}),
        ));
        assert!(linked.subagent);
        assert_eq!(linked.parent_turn_id.as_deref(), Some("parent-response"));

        for candidate in [
            record(json!({"subagent": true}), json!({})),
            record(
                json!({"subagent": "true", "parent_response_id": "parent"}),
                json!({}),
            ),
            record(
                json!({"client_name": "subagent"}),
                json!({"parent.turn.id": ["parent"]}),
            ),
        ] {
            assert!(!conversation_hints(&candidate).subagent);
        }
    }

    #[test]
    fn archive_execution_metadata_keeps_only_bounded_non_secret_declarations() {
        let hints = conversation_hints(&record(
            json!({
                "session_name": "nightly fulfilment",
                "trace_id": "trace-7",
                "agent_id": "worker-2",
                "parent_agent_id": "scheduler",
                "task_kind": "background",
                "session_labels": {
                    "workflow": "fulfilment",
                    "environment": "production",
                    "access-token": "must-drop",
                    "numeric": 7
                }
            }),
            json!({}),
        ));
        assert_eq!(hints.session_name.as_deref(), Some("nightly fulfilment"));
        assert_eq!(hints.trace_id.as_deref(), Some("trace-7"));
        assert_eq!(hints.agent_id.as_deref(), Some("worker-2"));
        assert_eq!(hints.parent_agent_id.as_deref(), Some("scheduler"));
        assert_eq!(hints.task_kind.as_deref(), Some("background"));
        assert_eq!(hints.labels.len(), 2);
        assert!(!hints.labels.contains_key("access-token"));
        assert!(!hints.labels.contains_key("numeric"));
    }
}
