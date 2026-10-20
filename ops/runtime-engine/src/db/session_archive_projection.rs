use super::*;

pub(crate) async fn add_archive_record_to_session_projection_in_transaction(
    tx: &mut Transaction<'_, Any>,
    tenant_id: Uuid,
    key_id: Uuid,
    source: &str,
    external_request_id: &str,
) -> Result<(), AppError> {
    let inserted = sqlx::query(
        r#"INSERT INTO session_archive_totals (
               tenant_id, key_id, session_id, last_activity_at, requests, errors,
               input_tokens, output_tokens, duration_count, duration_sum_ms)
           SELECT tenant_id, key_id,
                  COALESCE(conversation_cluster_id, 'unlinked:' || key_id),
                  source_started_at, 1,
                  CASE WHEN status_code IS NOT NULL
                             AND (status_code < 200 OR status_code >= 400)
                       THEN 1 ELSE 0 END,
                  input_tokens, output_tokens,
                  CASE WHEN duration_ms IS NULL THEN 0 ELSE 1 END,
                  COALESCE(duration_ms, 0)
             FROM session_archive_unlinked_requests
            WHERE tenant_id = $1 AND key_id = $2 AND source = $3
              AND external_request_id = $4
           ON CONFLICT (tenant_id, key_id, session_id) DO UPDATE SET
               last_activity_at = CASE
                   WHEN session_archive_totals.last_activity_at < excluded.last_activity_at
                   THEN excluded.last_activity_at ELSE session_archive_totals.last_activity_at END,
               requests = session_archive_totals.requests + 1,
               errors = session_archive_totals.errors + excluded.errors,
               input_tokens = session_archive_totals.input_tokens + excluded.input_tokens,
               output_tokens = session_archive_totals.output_tokens + excluded.output_tokens,
               duration_count = session_archive_totals.duration_count + excluded.duration_count,
               duration_sum_ms = session_archive_totals.duration_sum_ms + excluded.duration_sum_ms"#,
    )
    .bind(tenant_id.to_string())
    .bind(key_id.to_string())
    .bind(source)
    .bind(external_request_id)
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(AppError::Internal);
    }
    Ok(())
}
