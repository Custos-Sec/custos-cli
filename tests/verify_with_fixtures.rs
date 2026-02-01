use wiremock::MockServer;

#[tokio::test]
async fn verify_with_fixtures_smoke() {
    // Simple smoke test to ensure mock server can start in CI; real integration
    // test lives in unit tests inside src/ files to access crate internals.
    let server = MockServer::start().await;
    println!("mock server at {}", server.uri());
    assert!(!server.uri().is_empty());
}
