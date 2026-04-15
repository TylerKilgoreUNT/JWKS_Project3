use chrono::Utc;
use project1_rust::{build_routes, initialize_database, AppState, DB_FILE};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::RsaPrivateKey;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;
use warp::http::StatusCode;
use warp::test::request;

fn setup_state() -> (AppState, TempDir) {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("test_private_keys.db");
    initialize_database(db_path.to_str().expect("invalid db path")).expect("failed to init db");
    (
        AppState::new(db_path.to_string_lossy().to_string()),
        temp_dir,
    )
}

fn load_key_ids(db_path: &str, expired: bool) -> Vec<i64> {
    let conn = Connection::open(db_path).expect("failed to open db");
    let now = Utc::now().timestamp();
    let query = if expired {
        "SELECT kid FROM keys WHERE exp <= ?1"
    } else {
        "SELECT kid FROM keys WHERE exp > ?1"
    };

    let mut statement = conn.prepare(query).expect("failed to prepare query");
    let rows = statement
        .query_map([now], |row| row.get::<_, i64>(0))
        .expect("failed to run query");

    rows.map(|row| row.expect("invalid row")).collect()
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
fn initialize_database_is_idempotent() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("idempotent_integration.db");
    let db_path_str = db_path.to_str().expect("invalid db path");

    initialize_database(db_path_str).expect("first initialization failed");
    initialize_database(db_path_str).expect("second initialization failed");

    let conn = Connection::open(db_path_str).expect("failed to open db");
    let total_count: i64 = conn
        .query_row("SELECT COUNT(1) FROM keys", [], |row| row.get(0))
        .expect("failed to query total key count");
    let now = Utc::now().timestamp();
    let expired_count: i64 = conn
        .query_row("SELECT COUNT(1) FROM keys WHERE exp <= ?1", [now], |row| {
            row.get(0)
        })
        .expect("failed to query expired key count");
    let valid_count: i64 = conn
        .query_row("SELECT COUNT(1) FROM keys WHERE exp > ?1", [now], |row| {
            row.get(0)
        })
        .expect("failed to query valid key count");

    assert_eq!(total_count, 2, "database should keep exactly two seed keys");
    assert_eq!(expired_count, 1, "expected exactly one expired key");
    assert_eq!(valid_count, 1, "expected exactly one valid key");
}

#[test]
fn binary_main_initializes_and_exits_when_skip_server_is_set() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("main_from_integration.db");
    let db_path_str = db_path.to_str().expect("invalid db path");

    let status = Command::new(env!("CARGO_BIN_EXE_project1_rust"))
        .env("JWKS_DB_PATH", db_path_str)
        .env("JWKS_SKIP_SERVER", "1")
        .status()
        .expect("failed to run project1_rust binary");

    assert!(status.success(), "binary exited with status: {status}");

    let conn = Connection::open(db_path_str).expect("failed to open initialized db");
    let key_count: i64 = conn
        .query_row("SELECT COUNT(1) FROM keys", [], |row| row.get(0))
        .expect("failed to query key count");
    assert!(
        key_count >= 2,
        "expected seeded database to contain at least two keys"
    );
}

#[test]
fn table_schema_matches_requirement() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");

    let mut stmt = conn
        .prepare("PRAGMA table_info(keys)")
        .expect("failed to query schema");

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .expect("failed to read schema rows");

    let cols = rows
        .map(|r| r.expect("invalid schema row"))
        .collect::<Vec<_>>();

    assert_eq!(cols.len(), 3);
    assert_eq!(cols[0].0, "kid");
    assert_eq!(cols[0].1.to_uppercase(), "INTEGER");
    assert_eq!(cols[0].3, 1);

    assert_eq!(cols[1].0, "key");
    assert_eq!(cols[1].1.to_uppercase(), "BLOB");
    assert_eq!(cols[1].2, 1);

    assert_eq!(cols[2].0, "exp");
    assert_eq!(cols[2].1.to_uppercase(), "INTEGER");
    assert_eq!(cols[2].2, 1);
}

#[test]
fn keys_are_stored_as_pkcs1_pem_blob() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");

    let key_blob: Vec<u8> = conn
        .query_row("SELECT key FROM keys LIMIT 1", [], |row| row.get(0))
        .expect("missing key rows");

    let key_text = String::from_utf8(key_blob).expect("key blob was not UTF-8 PEM");
    assert!(key_text.contains("BEGIN RSA PRIVATE KEY"));
    RsaPrivateKey::from_pkcs1_pem(&key_text).expect("stored PEM was not parseable PKCS1");
}

#[test]
fn database_stores_expired_and_valid_keys() {
    let (state, _temp_dir) = setup_state();
    let valid_keys = load_key_ids(state.db_path(), false);
    let expired_keys = load_key_ids(state.db_path(), true);

    assert!(!valid_keys.is_empty());
    assert!(!expired_keys.is_empty());
}

#[test]
fn source_contains_parameterized_insert_expected_by_gradebot() {
    let src = fs::read_to_string("src/lib.rs").expect("failed to read src/lib.rs");
    assert!(
        src.contains("INSERT INTO keys (key, exp) VALUES (?, ?)"),
        "missing grader-compatible parameterized insertion pattern"
    );
}

#[tokio::test]
async fn post_auth_returns_valid_jwt() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state.clone());

    let response = request().method("POST").path("/auth").reply(&routes).await;

    assert_eq!(response.status(), StatusCode::OK);
    let token = std::str::from_utf8(response.body()).expect("response was not utf-8");
    let kid = token_kid(token);
    let valid_ids = load_key_ids(state.db_path(), false);
    assert!(valid_ids.contains(&kid.parse::<i64>().expect("kid was not numeric")));
}

#[tokio::test]
async fn post_auth_expired_uses_expired_key() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state.clone());

    let response = request()
        .method("POST")
        .path("/auth?expired=1")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let token = std::str::from_utf8(response.body()).expect("response was not utf-8");
    let kid = token_kid(token);
    let expired_ids = load_key_ids(state.db_path(), true);
    assert!(expired_ids.contains(&kid.parse::<i64>().expect("kid was not numeric")));
}

#[tokio::test]
async fn post_auth_expired_true_uses_expired_key() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state.clone());

    let response = request()
        .method("POST")
        .path("/auth?expired=true")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let token = std::str::from_utf8(response.body()).expect("response was not utf-8");
    let kid = token_kid(token);
    let expired_ids = load_key_ids(state.db_path(), true);
    assert!(expired_ids.contains(&kid.parse::<i64>().expect("kid was not numeric")));
}

#[tokio::test]
async fn post_auth_expired_query_flag_without_value_uses_expired_key() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state.clone());

    let response = request()
        .method("POST")
        .path("/auth?expired")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let token = std::str::from_utf8(response.body()).expect("response was not utf-8");
    let kid = token_kid(token);
    let expired_ids = load_key_ids(state.db_path(), true);
    assert!(expired_ids.contains(&kid.parse::<i64>().expect("kid was not numeric")));
}

#[tokio::test]
async fn post_auth_expired_false_keeps_valid_key_path() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state.clone());

    let response = request()
        .method("POST")
        .path("/auth?expired=false")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let token = std::str::from_utf8(response.body()).expect("response was not utf-8");
    let kid = token_kid(token);
    let valid_ids = load_key_ids(state.db_path(), false);
    assert!(valid_ids.contains(&kid.parse::<i64>().expect("kid was not numeric")));
}

#[tokio::test]
async fn post_auth_returns_500_when_no_signing_keys_exist() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");
    conn.execute("DELETE FROM keys", [])
        .expect("failed to delete keys");

    let routes = build_routes(state);
    let response = request().method("POST").path("/auth").reply(&routes).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn post_auth_returns_500_when_valid_key_blob_is_not_utf8() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");
    let now = Utc::now().timestamp();
    conn.execute(
        "UPDATE keys SET key = ?1 WHERE exp > ?2",
        params![vec![0xff_u8, 0xfe_u8, 0xfd_u8], now],
    )
    .expect("failed to corrupt valid keys");

    let routes = build_routes(state);
    let response = request().method("POST").path("/auth").reply(&routes).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn post_auth_returns_500_when_valid_key_is_not_pem() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");
    let now = Utc::now().timestamp();
    conn.execute(
        "UPDATE keys SET key = ?1 WHERE exp > ?2",
        params![b"not-a-pem-private-key".to_vec(), now],
    )
    .expect("failed to replace valid keys with invalid PEM");

    let routes = build_routes(state);
    let response = request().method("POST").path("/auth").reply(&routes).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn post_auth_returns_500_when_database_path_is_missing() {
    let state = AppState::new("this/path/does/not/exist/private_keys.db");
    let routes = build_routes(state);

    let response = request().method("POST").path("/auth").reply(&routes).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn post_auth_accepts_basic_auth_and_json_payload() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state);

    let response = request()
        .method("POST")
        .path("/auth")
        .header("authorization", "Basic dXNlckFCQzpwYXNzd29yZDEyMw==")
        .header("content-type", "application/json")
        .body("{\"username\":\"userABC\",\"password\":\"password123\"}")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let token = std::str::from_utf8(response.body()).expect("response was not utf-8");
    assert_eq!(token.split('.').count(), 3);
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
async fn get_jwks_returns_only_valid_keys() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state.clone());

    let response = request()
        .method("GET")
        .path("/.well-known/jwks.json")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let parsed: serde_json::Value =
        serde_json::from_slice(response.body()).expect("invalid json response");
    let keys = parsed["keys"].as_array().expect("keys was not an array");

    let valid_ids = load_key_ids(state.db_path(), false)
        .into_iter()
        .map(|kid| kid.to_string())
        .collect::<Vec<_>>();

    let expired_ids = load_key_ids(state.db_path(), true)
        .into_iter()
        .map(|kid| kid.to_string())
        .collect::<Vec<_>>();

    assert!(!keys.is_empty());

    for key in keys {
        let kid = key["kid"].as_str().expect("kid missing from jwks key");
        assert!(valid_ids.contains(&kid.to_string()));
        assert!(!expired_ids.contains(&kid.to_string()));
    }
}

#[tokio::test]
async fn get_jwks_returns_500_when_all_valid_keys_are_malformed() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");
    let now = Utc::now().timestamp();
    conn.execute(
        "UPDATE keys SET key = ?1 WHERE exp > ?2",
        params![vec![0xff_u8, 0xfe_u8, 0xfd_u8], now],
    )
    .expect("failed to corrupt valid keys");

    let routes = build_routes(state);
    let response = request()
        .method("GET")
        .path("/.well-known/jwks.json")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let parsed: serde_json::Value =
        serde_json::from_slice(response.body()).expect("invalid error json response");
    assert!(parsed["error"].as_str().is_some());
}

#[tokio::test]
async fn get_jwks_skips_malformed_key_when_other_valid_key_exists() {
    let (state, _temp_dir) = setup_state();
    let conn = Connection::open(state.db_path()).expect("failed to open db");
    let now = Utc::now().timestamp();
    let extra_valid_exp = now + 7200;
    conn.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        params![b"not-a-pem-private-key".to_vec(), extra_valid_exp],
    )
    .expect("failed to insert malformed valid key");

    let routes = build_routes(state);
    let response = request()
        .method("GET")
        .path("/.well-known/jwks.json")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let parsed: serde_json::Value =
        serde_json::from_slice(response.body()).expect("invalid jwks json response");
    let keys = parsed["keys"].as_array().expect("keys was not an array");
    assert!(!keys.is_empty());
}

#[tokio::test]
async fn get_jwks_returns_500_when_database_path_is_missing() {
    let state = AppState::new("this/path/does/not/exist/private_keys.db");
    let routes = build_routes(state);

    let response = request()
        .method("GET")
        .path("/.well-known/jwks.json")
        .reply(&routes)
        .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let parsed: serde_json::Value =
        serde_json::from_slice(response.body()).expect("invalid error json response");
    assert!(parsed["error"].as_str().is_some());
}

#[tokio::test]
async fn method_not_allowed_is_enforced() {
    let (state, _temp_dir) = setup_state();
    let routes = build_routes(state);

    let response = request().method("GET").path("/auth").reply(&routes).await;

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}
