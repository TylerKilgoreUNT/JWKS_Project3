use aes_gcm::aead::KeyInit;
use chrono::Utc;
use project1_rust::{build_routes, initialize_database, AppState, DB_FILE};
use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::Digest;
use std::process::Command;
use tempfile::TempDir;
use warp::http::StatusCode;
use warp::test::request;

const TEST_AES_KEY: &str = "integration-test-encryption-key";

fn setup_state() -> (AppState, TempDir) {
    std::env::set_var("NOT_MY_KEY", TEST_AES_KEY);

    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("test_private_keys.db");
    initialize_database(db_path.to_str().expect("invalid db path")).expect("failed to init db");
    (
        AppState::new(db_path.to_string_lossy().to_string()),
        temp_dir,
    )
}

fn token_kid(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let decoded = base64_url::decode(parts[0]).expect("invalid JWT header encoding");
    let json_value: serde_json::Value =
        serde_json::from_slice(&decoded).expect("invalid JWT header json");
    json_value["kid"].as_str().expect("missing kid").to_string()
}

fn token_payload(token: &str) -> Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let decoded = base64_url::decode(parts[1]).expect("invalid JWT payload encoding");
    serde_json::from_slice(&decoded).expect("invalid JWT payload json")
}

#[test]
fn db_filename_matches_requirement() {
    assert_eq!(DB_FILE, "totally_not_my_privateKeys.db");
}

#[test]
fn initialize_database_creates_required_tables() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");

    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .expect("failed to query table list");

    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .expect("failed to iterate table list");

    let table_names: Vec<String> = rows.map(|row| row.expect("invalid table row")).collect();

    assert!(table_names.contains(&"keys".to_string()));
    assert!(table_names.contains(&"users".to_string()));
    assert!(table_names.contains(&"auth_logs".to_string()));
}

#[test]
fn keys_are_encrypted_at_rest() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");

    let key_blob: Vec<u8> = conn
        .query_row("SELECT key FROM keys LIMIT 1", [], |row| row.get(0))
        .expect("missing key rows");

    let blob_text = String::from_utf8_lossy(&key_blob);

    assert!(
        key_blob.len() > 12,
        "encrypted blob should contain nonce + ciphertext"
    );
    assert!(
        !blob_text.contains("BEGIN RSA PRIVATE KEY"),
        "private key must not be stored as plaintext PEM"
    );
}

#[test]
fn binary_main_initializes_and_exits_when_skip_server_is_set() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("main_from_integration.db");
    let db_path_str = db_path.to_str().expect("invalid db path");

    let status = Command::new(env!("CARGO_BIN_EXE_project1_rust"))
        .env("JWKS_DB_PATH", db_path_str)
        .env("JWKS_SKIP_SERVER", "1")
        .env("NOT_MY_KEY", TEST_AES_KEY)
        .status()
        .expect("failed to run project1_rust binary");

    assert!(status.success(), "binary exited with status: {status}");
}

#[tokio::test]
async fn register_creates_user_with_hashed_password() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state.clone());

    let response = request()
        .method("POST")
        .path("/register")
        .header("content-type", "application/json")
        .body("{\"username\":\"MyCoolUsername\",\"email\":\"person@example.com\"}")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let parsed: serde_json::Value =
        serde_json::from_slice(response.body()).expect("invalid response json");
    let password = parsed["password"]
        .as_str()
        .expect("password missing from response");

    assert!(!password.is_empty());

    let conn = Connection::open(state.db_path()).expect("failed to open db");
    let (stored_username, stored_hash): (String, String) = conn
        .query_row(
            "SELECT username, password_hash FROM users WHERE username = ?1",
            ["MyCoolUsername"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("user should be present in users table");

    assert_eq!(stored_username, "MyCoolUsername");
    assert!(stored_hash.starts_with("$argon2"));
}

#[tokio::test]
async fn register_rejects_empty_username() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state);

    let response = request()
        .method("POST")
        .path("/register")
        .header("content-type", "application/json")
        .body("{\"username\":\"   \",\"email\":\"blank@example.com\"}")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_rejects_duplicate_username_or_email() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state);

    let first = request()
        .method("POST")
        .path("/register")
        .header("content-type", "application/json")
        .body("{\"username\":\"dupe-user\",\"email\":\"dupe@example.com\"}")
        .reply(&routes)
        .await;
    assert_eq!(first.status(), StatusCode::CREATED);

    let duplicate_username = request()
        .method("POST")
        .path("/register")
        .header("content-type", "application/json")
        .body("{\"username\":\"dupe-user\",\"email\":\"another@example.com\"}")
        .reply(&routes)
        .await;
    assert_eq!(duplicate_username.status(), StatusCode::CONFLICT);

    let duplicate_email = request()
        .method("POST")
        .path("/register")
        .header("content-type", "application/json")
        .body("{\"username\":\"another-user\",\"email\":\"dupe@example.com\"}")
        .reply(&routes)
        .await;
    assert_eq!(duplicate_email.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn post_auth_logs_request_ip_and_user_id_on_success() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state.clone());

    let register_response = request()
        .method("POST")
        .path("/register")
        .header("content-type", "application/json")
        .body("{\"username\":\"auth-user\",\"email\":\"auth@example.com\"}")
        .reply(&routes)
        .await;

    assert_eq!(register_response.status(), StatusCode::CREATED);

    let auth_response = request()
        .method("POST")
        .path("/auth")
        .header("content-type", "application/json")
        .body("{\"username\":\"auth-user\"}")
        .reply(&routes)
        .await;

    assert_eq!(auth_response.status(), StatusCode::OK);

    let conn = Connection::open(state.db_path()).expect("failed to open db");

    let user_id: i64 = conn
        .query_row(
            "SELECT id FROM users WHERE username = ?1",
            ["auth-user"],
            |row| row.get(0),
        )
        .expect("expected existing user id");

    let (request_ip, logged_user_id): (String, Option<i64>) = conn
        .query_row(
            "SELECT request_ip, user_id FROM auth_logs ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("expected auth log row");

    assert_eq!(request_ip, "unknown");
    assert_eq!(logged_user_id, Some(user_id));
}

#[tokio::test]
async fn auth_rate_limiter_returns_429_after_10_requests_in_window() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state);

    for _ in 0..10 {
        let response = request().method("POST").path("/auth").reply(&routes).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    let limited = request().method("POST").path("/auth").reply(&routes).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn auth_returns_500_for_non_utf8_decrypted_private_key() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");
    let now = Utc::now().timestamp();

    // Keep nonce length valid but force decrypted payload to invalid UTF-8 bytes.
    let malformed_blob = vec![0_u8; 13];
    conn.execute(
        "UPDATE keys SET key = ?1 WHERE exp > ?2",
        params![malformed_blob, now],
    )
    .expect("failed to update key blob");

    let routes = build_routes(state);
    let response = request().method("POST").path("/auth").reply(&routes).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn auth_returns_500_for_non_pem_private_key() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");
    let now = Utc::now().timestamp();

    // Encrypt known non-PEM plaintext with the same test key setup.
    let payload = b"definitely-not-a-pem";
    let mut hasher = sha2::Sha256::new();
    hasher.update(TEST_AES_KEY.as_bytes());
    let digest = hasher.finalize();
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&digest[..32]).expect("cipher create failed");
    let nonce_bytes = [7_u8; 12];
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = aes_gcm::aead::Aead::encrypt(&cipher, nonce, payload.as_ref())
        .expect("encryption should succeed");

    let mut blob = nonce_bytes.to_vec();
    blob.extend_from_slice(&ciphertext);

    conn.execute(
        "UPDATE keys SET key = ?1 WHERE exp > ?2",
        params![blob, now],
    )
    .expect("failed to update key blob");

    let routes = build_routes(state);
    let response = request().method("POST").path("/auth").reply(&routes).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn auth_exp_claim_respects_expired_mode() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state);

    let valid_response = request().method("POST").path("/auth").reply(&routes).await;
    assert_eq!(valid_response.status(), StatusCode::OK);
    let valid_token = std::str::from_utf8(valid_response.body()).expect("valid token utf-8");
    let valid_payload = token_payload(valid_token);

    let expired_response = request()
        .method("POST")
        .path("/auth?expired=1")
        .reply(&routes)
        .await;
    assert_eq!(expired_response.status(), StatusCode::OK);
    let expired_token = std::str::from_utf8(expired_response.body()).expect("expired token utf-8");
    let expired_payload = token_payload(expired_token);

    let now = Utc::now().timestamp();
    let valid_exp = valid_payload["exp"].as_i64().expect("valid exp missing");
    let expired_exp = expired_payload["exp"]
        .as_i64()
        .expect("expired exp missing");

    assert!(valid_exp > now);
    assert!(expired_exp <= now);
}

#[tokio::test]
async fn jwks_and_auth_still_work() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state);

    let auth_response = request().method("POST").path("/auth").reply(&routes).await;
    assert_eq!(auth_response.status(), StatusCode::OK);
    let token = std::str::from_utf8(auth_response.body()).expect("jwt not utf-8");
    assert!(!token_kid(token).is_empty());

    let jwks_response = request()
        .method("GET")
        .path("/.well-known/jwks.json")
        .reply(&routes)
        .await;

    assert_eq!(jwks_response.status(), StatusCode::OK);

    let parsed: serde_json::Value =
        serde_json::from_slice(jwks_response.body()).expect("invalid jwks json response");
    let keys = parsed["keys"].as_array().expect("keys was not an array");
    assert!(!keys.is_empty());
}

#[tokio::test]
async fn jwks_returns_500_when_all_valid_keys_are_malformed() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");
    let now = Utc::now().timestamp();

    // Nonce-sized but undecryptable payload to make all valid keys malformed.
    conn.execute(
        "UPDATE keys SET key = ?1 WHERE exp > ?2",
        params![vec![0_u8; 13], now],
    )
    .expect("failed to corrupt valid keys");

    let routes = build_routes(state);
    let response = request()
        .method("GET")
        .path("/.well-known/jwks.json")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn method_not_allowed_is_enforced() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state);

    let get_auth = request().method("GET").path("/auth").reply(&routes).await;
    assert_eq!(get_auth.status(), StatusCode::METHOD_NOT_ALLOWED);

    let get_register = request()
        .method("GET")
        .path("/register")
        .reply(&routes)
        .await;
    assert_eq!(get_register.status(), StatusCode::METHOD_NOT_ALLOWED);

    let post_jwks = request()
        .method("POST")
        .path("/.well-known/jwks.json")
        .reply(&routes)
        .await;
    assert_eq!(post_jwks.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn auth_and_jwks_fail_when_encryption_env_missing_or_empty() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state.clone());

    std::env::remove_var("NOT_MY_KEY");
    let auth_missing_key = request().method("POST").path("/auth").reply(&routes).await;
    assert_eq!(auth_missing_key.status(), StatusCode::INTERNAL_SERVER_ERROR);

    std::env::set_var("NOT_MY_KEY", "");
    let jwks_empty_key = request()
        .method("GET")
        .path("/.well-known/jwks.json")
        .reply(&routes)
        .await;
    assert_eq!(jwks_empty_key.status(), StatusCode::INTERNAL_SERVER_ERROR);

    std::env::set_var("NOT_MY_KEY", TEST_AES_KEY);
}
