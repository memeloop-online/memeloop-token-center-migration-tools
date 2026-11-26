//! Isolated object-store contract. All locators and body values are synthetic.
use super::*;
use memeloop_token_center::{config::ArchiveBackend, conversation};

async fn decoded(archive: &ArchiveStore, locator: &str) -> Vec<u8> {
    let mut stream = archive.open_stream(locator, None).await.unwrap().stream;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk.unwrap());
    }
    body
}

#[tokio::test]
async fn rustfs_legacy_plain_and_compressed_sources_preserve_canonical_semantics() {
    // This test must exercise the workflow's real isolated RustFS fixture.
    // Missing fixture configuration is a failure rather than an ignored test.
    let mut config = Config::for_test("sqlite::memory:".into());
    config.archive_backend = ArchiveBackend::S3;
    config.s3_endpoint =
        Some(std::env::var("MTC_RUSTFS_TEST_ENDPOINT").expect("isolated RustFS endpoint"));
    config.s3_bucket =
        Some(std::env::var("MTC_RUSTFS_TEST_BUCKET").expect("isolated RustFS bucket"));
    config.s3_access_key =
        Some(std::env::var("MTC_RUSTFS_TEST_ACCESS_KEY").expect("isolated RustFS credential"));
    config.s3_secret_key =
        Some(std::env::var("MTC_RUSTFS_TEST_SECRET_KEY").expect("isolated RustFS credential"));
    config.s3_region = "us-east-1".into();
    config.s3_allow_http = true;
    let archive = ArchiveStore::from_config(&config).await.unwrap();
    let tenant = Uuid::now_v7();
    let request_id = Uuid::now_v7();
    let attempt = Uuid::now_v7();
    let text = "synthetic工具😀".repeat(20000);
    let request_value = serde_json::json!({"model":"fixture","messages":[
        {"role":"user","content":text},
        {"role":"assistant","tool_calls":[{"id":"fixture-call","type":"function","function":{"name":"echo","arguments":serde_json::to_string(&serde_json::json!({"input":text})).unwrap()}}]},
        {"role":"tool","tool_call_id":"fixture-call","content":text}
    ]});
    let response_value = serde_json::json!({"object":"response","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[
        {"type":"reasoning","summary":[{"type":"summary_text","text":"synthetic available reasoning"}]},
        {"type":"message","role":"assistant","content":[{"type":"output_text","text":"synthetic partial answer"}]}
    ]});
    let request = Bytes::from(serde_json::to_vec(&request_value).unwrap());
    let response = Bytes::from(serde_json::to_vec(&response_value).unwrap());
    let request_locator = format!("staging/proxy/{request_id}/request/{attempt}/body.json");
    let response_prefix = format!("staging/proxy/{request_id}/response/{attempt}/body");
    archive
        .put(&request_locator, request.clone())
        .await
        .unwrap();
    let mut writer = archive
        .start_compressed_writer(&response_prefix)
        .await
        .unwrap();
    writer.write(response.clone()).await.unwrap();
    let response_object = writer.finish_staged().await.unwrap();
    assert_eq!(
        response_object.object_locator,
        format!("{response_prefix}.mtcz1")
    );
    let mut rebound = Vec::new();
    for (locator, expected) in [
        (&request_locator, &request),
        (&response_object.object_locator, &response),
    ] {
        let source = Source {
            locator: locator.clone(),
            decoded_bytes: expected.len() as u64,
            decoded_sha256: format!("{:x}", Sha256::digest(expected)),
        };
        verify_source(&archive, &source).await.unwrap();
        let plain = decoded(&archive, locator).await;
        assert_eq!(plain.as_slice(), expected.as_ref());
        let cas = archive
            .put_tenant_content(tenant, Bytes::from(plain))
            .await
            .unwrap();
        assert_ne!(&cas.object_locator, locator);
        verify_source(
            &archive,
            &Source {
                locator: cas.object_locator.clone(),
                decoded_bytes: source.decoded_bytes,
                decoded_sha256: source.decoded_sha256,
            },
        )
        .await
        .unwrap();
        let reread = decoded(&archive, &cas.object_locator).await;
        assert_eq!(reread.as_slice(), expected.as_ref());
        rebound.push(serde_json::from_slice::<serde_json::Value>(&reread).unwrap());
        // Both original sources remain readable after publishing the target.
        assert_eq!(
            decoded(&archive, locator).await.as_slice(),
            expected.as_ref()
        );
    }
    let original = conversation::session_body_from_documents(&request_value, &response_value);
    let migrated = conversation::session_body_from_documents(&rebound[0], &rebound[1]);
    assert_eq!(original, migrated);
    let (old_atoms, old_nodes) = original.into_prefix();
    let (new_atoms, new_nodes) = migrated.into_prefix();
    assert_eq!(old_atoms.len(), new_atoms.len());
    for (before, after) in old_atoms.iter().zip(&new_atoms) {
        assert_eq!(before.content, after.content);
        assert_eq!(before.content_hash, after.content_hash);
    }
    assert_eq!(
        old_nodes.last().unwrap().node_hash,
        new_nodes.last().unwrap().node_hash
    );
    assert_eq!(response_value["status"], "incomplete");
}
