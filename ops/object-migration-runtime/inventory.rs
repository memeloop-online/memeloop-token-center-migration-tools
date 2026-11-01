use super::*;

pub(super) async fn inventory(pool: &PgPool) -> Result<serde_json::Value> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let mut fields = Vec::new();
    for field in std::iter::once(payloads::SourceField::Atom).chain(payloads::FIELDS) {
        let (table, _, column) = field.columns();
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) AS rows, COALESCE(SUM(octet_length({column})), 0)::BIGINT AS bytes
             FROM {table} WHERE {column} IS NOT NULL"
        )))
        .fetch_one(&mut *transaction)
        .await?;
        fields.push(serde_json::json!({
            "field":field, "rows":row.try_get::<i64,_>("rows")?,
            "exact_text_bytes":row.try_get::<i64,_>("bytes")?,
        }));
    }
    let mut raw = Vec::new();
    for (table, columns) in [
        (
            "request_records",
            &["request_object", "response_object"][..],
        ),
        (
            "session_archive_import_records",
            &[
                "request_object",
                "response_object",
                "previous_request_object",
                "previous_response_object",
            ][..],
        ),
        (
            "session_archive_unlinked_requests",
            &["request_object", "response_object"][..],
        ),
        (
            "session_archive_quarantine_records",
            &["request_object", "response_object"][..],
        ),
        (
            "session_archive_quarantine_record_versions",
            &["request_object", "response_object"][..],
        ),
    ] {
        for column in columns {
            let row = sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*) AS rows,
                 COUNT(*) FILTER (WHERE {column} IS NULL OR {column} = '') AS missing,
                 COUNT(*) FILTER (WHERE {column} LIKE 'gap://%' OR {column} LIKE 'metadata-only-json:%' OR {column} LIKE 'provider-reference-json:%') AS gaps,
                 COUNT(*) FILTER (WHERE {column} LIKE 'inline-json:%') AS inline_rows,
                 COALESCE(SUM(CASE WHEN {column} LIKE 'inline-json:%' THEN octet_length({column}) - 12 ELSE 0 END), 0)::BIGINT AS inline_bytes
                 FROM {table}"
            ))).fetch_one(&mut *transaction).await?;
            raw.push(serde_json::json!({
                "table":table, "column":column, "rows":row.try_get::<i64,_>("rows")?,
                "missing":row.try_get::<i64,_>("missing")?, "gaps":row.try_get::<i64,_>("gaps")?,
                "inline_rows":row.try_get::<i64,_>("inline_rows")?,
                "exact_inline_bytes":row.try_get::<i64,_>("inline_bytes")?,
            }));
        }
    }
    let mut spools = Vec::new();
    for side in ["request", "response"] {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) AS headers,
             COUNT(*) FILTER (WHERE chunk_count > 0 AND NOT EXISTS (
                 SELECT 1 FROM {side}_archive_spool_chunks c WHERE c.request_id = s.request_id
             )) AS headers_without_retained_chunks,
             (SELECT COUNT(*) FROM {side}_archive_spool_chunks) AS chunks,
             (SELECT COALESCE(SUM(octet_length(ciphertext)), 0)::BIGINT FROM {side}_archive_spool_chunks) AS cipher_bytes
             FROM {side}_archive_spools s"
        ))).fetch_one(&mut *transaction).await?;
        spools.push(serde_json::json!({
            "side":side, "headers":row.try_get::<i64,_>("headers")?,
            "headers_without_retained_chunks":row.try_get::<i64,_>("headers_without_retained_chunks")?,
            "chunks":row.try_get::<i64,_>("chunks")?, "cipher_bytes":row.try_get::<i64,_>("cipher_bytes")?,
        }));
    }
    // Probe before querying: a missing relation aborts PostgreSQL's snapshot,
    // hiding otherwise useful historical counts. Absence is unknown, never 0.
    let media_present: bool =
        sqlx::query_scalar("SELECT to_regclass('public.conversation_media_parts') IS NOT NULL")
            .fetch_one(&mut *transaction)
            .await?;
    let media = if media_present {
        let row = sqlx::query("SELECT COUNT(*) AS rows, COALESCE(SUM(byte_length), 0)::BIGINT AS bytes FROM conversation_media_parts")
            .fetch_one(&mut *transaction).await?;
        serde_json::json!({
            "state":"counted", "rows":row.try_get::<i64,_>("rows")?,
            "indexed_bytes":row.try_get::<i64,_>("bytes")?,
        })
    } else {
        serde_json::json!({"state":"source_table_absent", "rows":null, "indexed_bytes":null})
    };
    transaction.commit().await?;
    Ok(serde_json::json!({
        "format_version":1, "fields":fields, "raw_sources":raw, "spools":spools,
        "media":media, "inventory_complete":media_present,
        "missing_source_tables":if media_present { Vec::<&str>::new() } else { vec!["conversation_media_parts"] },
        "durable_object_roots":"not_scanned_by_sql_inventory",
        "object_bytes_verified":false, "complete_training_fidelity_certified":false,
    }))
}

pub(super) fn require_complete(value: &serde_json::Value) -> Result<()> {
    if value["inventory_complete"] != true {
        return Err("source SQL inventory incomplete; missing tables remain unknown (see missing_source_tables)".into());
    }
    Ok(())
}
