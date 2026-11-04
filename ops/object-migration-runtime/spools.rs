use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use futures_util::StreamExt;
use memeloop_token_center::archive::CasArchiveObject;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpoolCursor {
    side: String,
    request_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpoolReceipt {
    format_version: u32,
    identity: String,
    cursor: SpoolCursor,
    tenant_id: Uuid,
    reservation_id: Uuid,
    state: String,
    chunks: u64,
    object: CasArchiveObject,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SpoolCheckpoint {
    format_version: u32,
    identity: String,
    cursor: SpoolCursor,
    pub(super) rows: u64,
    pub(super) chunks: u64,
    pub(super) bytes: u64,
    digest: String,
    complete: bool,
    pub(super) verified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    bytes: String,
}

fn key(pepper: &[u8]) -> Result<[u8; 32]> {
    let derivation = hkdf::Hkdf::<sha2::Sha256>::new(
        Some(b"memeloop-token-center/private-envelope/hkdf-sha256/v2"),
        pepper,
    );
    let mut key = [0; 32];
    derivation
        .expand(b"chacha20poly1305-key", &mut key)
        .map_err(|_| "legacy key derivation failed")?;
    Ok(key)
}

#[allow(clippy::too_many_arguments)]
fn decode(
    pepper: &[u8],
    tenant: Uuid,
    request: Uuid,
    reservation: Uuid,
    side: &str,
    seq: i64,
    ciphertext: &str,
    expected: i64,
) -> Result<Bytes> {
    if !matches!(side, "request" | "response")
        || seq < 0
        || !(1..=65536).contains(&expected)
        || ciphertext.len() > 262144
    {
        return Err("invalid legacy chunk metadata".into());
    }
    let (sealed, compressed, version) = match ciphertext.strip_prefix("zstd1.") {
        Some(sealed) => (sealed, true, 2),
        None => (ciphertext, false, 1),
    };
    let mut parts = sealed.split('.');
    if parts.next() != Some("v2") {
        return Err("unsupported legacy encryption envelope".into());
    }
    let nonce = URL_SAFE_NO_PAD.decode(parts.next().ok_or("missing nonce")?)?;
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| "invalid nonce")?;
    let payload = URL_SAFE_NO_PAD.decode(parts.next().ok_or("missing encrypted payload")?)?;
    if parts.next().is_some() {
        return Err("trailing legacy envelope fields".into());
    }
    let aad = format!(
        "memeloop-token-center/{side}-archive-spool/v{version}/{tenant}/{request}/{reservation}/{seq}"
    );
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key(pepper)?).map_err(|_| "invalid legacy key")?;
    let plain = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &payload,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "legacy chunk authentication failed")?;
    let envelope: Envelope = serde_json::from_slice(&plain)?;
    if envelope.bytes.len() > 87382 {
        return Err("legacy chunk envelope exceeds recorded format".into());
    }
    let bytes = URL_SAFE_NO_PAD.decode(envelope.bytes)?;
    let bytes = if compressed {
        zstd::bulk::decompress(&bytes, usize::try_from(expected)?)?
    } else {
        bytes
    };
    if bytes.len() as i64 != expected {
        return Err("legacy plaintext chunk length mismatch".into());
    }
    Ok(Bytes::from(bytes))
}

impl Runner {
    pub(super) async fn transfer_spools(
        &self,
        pepper: &[u8],
        verify: bool,
    ) -> Result<SpoolCheckpoint> {
        let path = self.checkpoint.with_extension("spools.json");
        let mut checkpoint = match std::fs::File::open(&path) {
            Ok(file) => serde_json::from_reader::<_, SpoolCheckpoint>(file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => SpoolCheckpoint {
                format_version: 1,
                identity: self.identity.clone(),
                ..Default::default()
            },
            Err(error) => return Err(error.into()),
        };
        if checkpoint.format_version != 1 || checkpoint.identity != self.identity {
            return Err("spool checkpoint identity mismatch".into());
        }
        if verify && !checkpoint.complete {
            return Err("spool copy is incomplete".into());
        }
        if !verify && checkpoint.complete {
            return Ok(checkpoint);
        }
        if verify {
            checkpoint.verified = false;
            save_checkpoint(&path, &checkpoint)?;
        }
        let mut result = if verify {
            SpoolCheckpoint {
                format_version: 1,
                identity: self.identity.clone(),
                ..Default::default()
            }
        } else {
            checkpoint.clone()
        };
        loop {
            let row = sqlx::query(
                "WITH spools AS (
                 SELECT 'request' AS side, request_id, tenant_id, reservation_id, state, chunk_count, byte_count FROM request_archive_spools WHERE chunk_count > 0 AND EXISTS (SELECT 1 FROM request_archive_spool_chunks c WHERE c.request_id = request_archive_spools.request_id)
                 UNION ALL SELECT 'response', request_id, tenant_id, reservation_id, state, chunk_count, byte_count FROM response_archive_spools WHERE chunk_count > 0 AND EXISTS (SELECT 1 FROM response_archive_spool_chunks c WHERE c.request_id = response_archive_spools.request_id)
                 ) SELECT * FROM spools WHERE (side, request_id) > ($1, $2) ORDER BY side, request_id LIMIT 1",
            )
            .bind(&result.cursor.side).bind(&result.cursor.request_id)
            .fetch_optional(&self.pool).await?;
            let Some(row) = row else {
                break;
            };
            let side: String = row.try_get("side")?;
            let request_id: String = row.try_get("request_id")?;
            let tenant = Uuid::parse_str(row.try_get("tenant_id")?)?;
            let request = Uuid::parse_str(&request_id)?;
            let reservation = Uuid::parse_str(row.try_get("reservation_id")?)?;
            let expected_chunks = u64::try_from(row.try_get::<i64, _>("chunk_count")?)?;
            let expected_bytes = u64::try_from(row.try_get::<i64, _>("byte_count")?)?;
            let mut transaction = self.pool.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *transaction)
                .await?;
            let statement = match side.as_str() {
                "request" => {
                    "SELECT seq, byte_count, CASE WHEN octet_length(ciphertext) <= 262144 THEN ciphertext END AS ciphertext FROM request_archive_spool_chunks WHERE request_id = $1 ORDER BY seq"
                }
                "response" => {
                    "SELECT seq, byte_count, CASE WHEN octet_length(ciphertext) <= 262144 THEN ciphertext END AS ciphertext FROM response_archive_spool_chunks WHERE request_id = $1 ORDER BY seq"
                }
                _ => return Err("invalid spool side".into()),
            };
            let mut rows = sqlx::query(statement)
                .bind(&request_id)
                .fetch(&mut *transaction);
            let staging = format!(
                "migration-staging/conversation-v1/{}/{}",
                self.identity,
                Uuid::now_v7()
            );
            let mut writer = if verify {
                None
            } else {
                Some(self.target.start_writer(&staging).await?)
            };
            let mut digest = blake3::Hasher::new();
            let mut chunks = 0_u64;
            let mut bytes = 0_u64;
            while let Some(chunk) = rows.next().await {
                let chunk = chunk?;
                let seq: i64 = chunk.try_get("seq")?;
                if u64::try_from(seq)? != chunks {
                    return Err("spool chunk sequence gap".into());
                }
                let ciphertext: String = chunk
                    .try_get::<Option<String>, _>("ciphertext")?
                    .ok_or("oversized legacy ciphertext")?;
                let body = decode(
                    pepper,
                    tenant,
                    request,
                    reservation,
                    &side,
                    seq,
                    &ciphertext,
                    chunk.try_get("byte_count")?,
                )?;
                digest.update(&body);
                bytes += body.len() as u64;
                chunks += 1;
                if let Some(writer) = &mut writer {
                    writer.write(body).await?;
                }
            }
            drop(rows);
            transaction.commit().await?;
            if chunks != expected_chunks || bytes != expected_bytes {
                return Err("legacy spool count/byte mismatch; source retained".into());
            }
            let digest = digest.finalize().to_hex().to_string();
            let object = if let Some(writer) = writer {
                let staged = writer.finish_staged().await?;
                if staged.blake3_digest != digest || staged.size_bytes != bytes {
                    return Err("spool transfer hash mismatch".into());
                }
                let object = self
                    .target
                    .promote_staged_text_to_cas(tenant, &staged)
                    .await?;
                self.target.delete(&staged.object_locator).await?;
                object
            } else {
                CasArchiveObject {
                    object_locator: format!(
                        "tenants/{tenant}/cas/v1/blake3/{}/{digest}",
                        &digest[..2]
                    ),
                    blake3_digest: digest,
                    size_bytes: bytes,
                }
            };
            let cursor = SpoolCursor { side, request_id };
            let receipt = SpoolReceipt {
                format_version: 1,
                identity: self.identity.clone(),
                cursor: cursor.clone(),
                tenant_id: tenant,
                reservation_id: reservation,
                state: row.try_get("state")?,
                chunks,
                object,
            };
            let encoded = serde_json::to_vec(&receipt)?;
            let receipt_key = format!(
                "migration-receipts/conversation-v1/{}/spools/{}/{}.json",
                self.identity, cursor.side, request
            );
            if !verify {
                self.target
                    .put(&receipt_key, Bytes::from(encoded.clone()))
                    .await?;
            }
            if self.target.get_bounded(&receipt_key, 16384).await?.as_ref() != encoded {
                return Err("spool receipt/source mismatch".into());
            }
            self.target
                .verify_tenant_content(tenant, &receipt.object)
                .await?;
            let mut digest = blake3::Hasher::new();
            digest.update(result.digest.as_bytes());
            digest.update(&encoded);
            result.digest = digest.finalize().to_hex().to_string();
            result.rows += 1;
            result.chunks += chunks;
            result.bytes += bytes;
            result.cursor = cursor;
            if !verify {
                save_checkpoint(&path, &result)?;
            }
        }
        if verify {
            if result.rows != checkpoint.rows
                || result.chunks != checkpoint.chunks
                || result.bytes != checkpoint.bytes
                || result.digest != checkpoint.digest
            {
                return Err("spool aggregate reconciliation failed".into());
            }
            result.verified = true;
        }
        result.complete = true;
        save_checkpoint(&path, &result)?;
        Ok(result)
    }
}

#[cfg(test)]
pub(super) fn fixture_cipher(
    pepper: &[u8],
    tenant: Uuid,
    request: Uuid,
    reservation: Uuid,
    seq: i64,
    body: &[u8],
) -> String {
    let cipher = ChaCha20Poly1305::new_from_slice(&key(pepper).unwrap()).unwrap();
    let nonce = [7_u8; 12];
    let aad = format!(
        "memeloop-token-center/response-archive-spool/v1/{tenant}/{request}/{reservation}/{seq}"
    );
    let payload =
        serde_json::to_vec(&serde_json::json!({"bytes":URL_SAFE_NO_PAD.encode(body)})).unwrap();
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &payload,
                aad: aad.as_bytes(),
            },
        )
        .unwrap();
    format!(
        "v2.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext)
    )
}
