use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::Utc;
use jsonwebtoken::{encode as jwt_encode, Algorithm as JwtAlgorithm, EncodingKey, Header};
use rand::thread_rng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;
use warp::{http::StatusCode, Filter, Rejection, Reply};

/// SQLite filename required by the project rubric.
pub const DB_FILE: &str = "totally_not_my_privateKeys.db";

const TABLE_SCHEMA_KEYS: &str = "CREATE TABLE IF NOT EXISTS keys(\
    kid INTEGER PRIMARY KEY AUTOINCREMENT,\
    key BLOB NOT NULL,\
    exp INTEGER NOT NULL\
)";
const TABLE_SCHEMA_USERS: &str = "CREATE TABLE IF NOT EXISTS users(\
    id INTEGER PRIMARY KEY AUTOINCREMENT,\
    username TEXT NOT NULL UNIQUE,\
    password_hash TEXT NOT NULL,\
    email TEXT UNIQUE,\
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\
    last_login TIMESTAMP\
)";
const TABLE_SCHEMA_AUTH_LOGS: &str = "CREATE TABLE IF NOT EXISTS auth_logs(\
    id INTEGER PRIMARY KEY AUTOINCREMENT,\
    request_ip TEXT NOT NULL,\
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\
    user_id INTEGER,\
    FOREIGN KEY(user_id) REFERENCES users(id)\
)";

const ENCRYPTION_ENV: &str = "NOT_MY_KEY";
const KEY_LIFETIME_SECONDS: i64 = 3600;
const JWT_SUBJECT: &str = "userABC";
const JWT_NAME: &str = "userABC";
const RATE_LIMIT_COUNT: u32 = 10;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct AppState {
    db_path: Arc<String>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

impl AppState {
    pub fn new(db_path: impl Into<String>) -> Self {
        Self {
            db_path: Arc::new(db_path.into()),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
        }
    }

    pub fn db_path(&self) -> &str {
        self.db_path.as_str()
    }
}

#[derive(Debug)]
struct StoredKey {
    kid: i64,
    key_pem: Vec<u8>,
}

struct RateLimiter {
    window_started: Instant,
    count: u32,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            window_started: Instant::now(),
            count: 0,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_started) >= RATE_LIMIT_WINDOW {
            self.window_started = now;
            self.count = 0;
        }

        if self.count >= RATE_LIMIT_COUNT {
            return false;
        }

        self.count += 1;
        true
    }
}

#[derive(Serialize)]
struct JwtClaims {
    sub: &'static str,
    name: &'static str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    email: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    password: String,
}

#[derive(Deserialize)]
struct AuthRequest {
    username: Option<String>,
}

fn format_error(context: &str, err: impl std::fmt::Display) -> String {
    format!("{context}: {err}")
}

fn with_context<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> Result<T, String> {
    match result {
        Ok(value) => Ok(value),
        Err(err) => Err(format_error(context, err.to_string())),
    }
}

fn open_connection(db_path: &str) -> Result<Connection, String> {
    with_context(Connection::open(db_path), "failed to open SQLite database")
}

fn derive_encryption_key() -> Result<[u8; 32], String> {
    let raw = std::env::var(ENCRYPTION_ENV)
        .map_err(|_| format!("missing required environment variable {ENCRYPTION_ENV}"))?;
    if raw.trim().is_empty() {
        return Err(format!(
            "environment variable {ENCRYPTION_ENV} must not be empty"
        ));
    }

    // Derive a fixed-length AES-256 key from the provided environment secret.
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();

    let mut key = [0_u8; 32];
    key.copy_from_slice(&digest[..32]);
    Ok(key)
}

fn encrypt_private_key(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key = derive_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|err| format_error("failed to create AES-256-GCM cipher", err))?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|err| format_error("failed to encrypt private key", err))?;

    let mut stored = nonce_bytes.to_vec();
    stored.extend_from_slice(&ciphertext);
    Ok(stored)
}

fn decrypt_private_key(ciphertext_blob: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext_blob.len() <= 12 {
        return Err("encrypted private key payload was malformed".to_string());
    }

    let key = derive_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|err| format_error("failed to create AES-256-GCM cipher", err))?;

    let (nonce_bytes, ciphertext) = ciphertext_blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|err| format_error("failed to decrypt private key", err))
}

pub fn initialize_database(db_path: &str) -> Result<(), String> {
    let mut conn = open_connection(db_path)?;

    with_context(
        conn.execute(TABLE_SCHEMA_KEYS, []),
        "failed to create keys table",
    )?;
    with_context(
        conn.execute(TABLE_SCHEMA_USERS, []),
        "failed to create users table",
    )?;
    with_context(
        conn.execute(TABLE_SCHEMA_AUTH_LOGS, []),
        "failed to create auth_logs table",
    )?;

    ensure_seed_keys(&mut conn)?;
    Ok(())
}

fn ensure_seed_keys(conn: &mut Connection) -> Result<(), String> {
    let now = Utc::now().timestamp();
    let transaction = with_context(conn.transaction(), "failed to start seed transaction")?;

    let expired_count =
        transaction.query_row("SELECT COUNT(1) FROM keys WHERE exp <= ?1", [now], |row| {
            row.get(0)
        });
    let expired_count: i64 = with_context(expired_count, "failed to count expired keys")?;

    if expired_count == 0 {
        let expired_pem = generate_private_key_pem()?;
        let encrypted = encrypt_private_key(expired_pem.as_bytes())?;
        let expired_exp = now - KEY_LIFETIME_SECONDS;

        with_context(
            transaction.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                params![encrypted, expired_exp],
            ),
            "failed to insert expired key",
        )?;
    }

    let valid_count =
        transaction.query_row("SELECT COUNT(1) FROM keys WHERE exp > ?1", [now], |row| {
            row.get(0)
        });
    let valid_count: i64 = with_context(valid_count, "failed to count valid keys")?;

    if valid_count == 0 {
        let valid_pem = generate_private_key_pem()?;
        let encrypted = encrypt_private_key(valid_pem.as_bytes())?;
        let valid_exp = now + KEY_LIFETIME_SECONDS;

        with_context(
            transaction.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                params![encrypted, valid_exp],
            ),
            "failed to insert valid key",
        )?;
    }

    with_context(transaction.commit(), "failed to commit seed transaction")?;
    Ok(())
}

fn generate_private_key_pem() -> Result<String, String> {
    let private_key = with_context(
        RsaPrivateKey::new(&mut thread_rng(), 2048),
        "failed to generate RSA private key",
    )?;
    let pem = with_context(
        private_key.to_pkcs1_pem(LineEnding::LF),
        "failed to encode private key as PKCS1 PEM",
    )?;
    Ok(pem.to_string())
}

fn load_signing_key(db_path: &str, use_expired: bool) -> Result<StoredKey, String> {
    let conn = open_connection(db_path)?;
    let now = Utc::now().timestamp();

    let query = if use_expired {
        "SELECT kid, key FROM keys WHERE exp <= ?1 ORDER BY exp DESC LIMIT 1"
    } else {
        "SELECT kid, key FROM keys WHERE exp > ?1 ORDER BY exp ASC LIMIT 1"
    };

    let encrypted = conn
        .query_row(query, [now], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|err| format_error("failed to load signing key", err))?;

    let decrypted = decrypt_private_key(&encrypted.1)?;
    Ok(StoredKey {
        kid: encrypted.0,
        key_pem: decrypted,
    })
}

fn load_valid_private_keys(db_path: &str) -> Result<Vec<StoredKey>, String> {
    let conn = open_connection(db_path)?;
    let now = Utc::now().timestamp();

    let mut statement = with_context(
        conn.prepare("SELECT kid, key FROM keys WHERE exp > ?1 ORDER BY kid ASC"),
        "failed to prepare valid-key query",
    )?;

    let rows = statement.query_map([now], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
    });
    let rows = with_context(rows, "failed to execute valid-key query")?;

    let mut keys = Vec::new();
    for row in rows {
        let (kid, encrypted) = with_context(row, "failed to read key row")?;
        let key_pem = decrypt_private_key(&encrypted)?;
        keys.push(StoredKey { kid, key_pem });
    }

    Ok(keys)
}

fn create_user(db_path: &str, payload: RegisterRequest) -> Result<String, (StatusCode, String)> {
    if payload.username.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "username must not be empty".to_string(),
        ));
    }

    let password = Uuid::new_v4().to_string();

    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format_error("failed to configure Argon2", err),
        )
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format_error("failed to hash generated password", err),
            )
        })?
        .to_string();

    let conn = open_connection(db_path).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format_error("failed to open database", err),
        )
    })?;

    let result = conn.execute(
        "INSERT INTO users (username, password_hash, email) VALUES (?1, ?2, ?3)",
        params![payload.username.trim(), hash, payload.email],
    );

    match result {
        Ok(_) => Ok(password),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err((
                StatusCode::CONFLICT,
                "username or email already exists".to_string(),
            ))
        }
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format_error("failed to create user", err),
        )),
    }
}

fn should_use_expired_key(params: &HashMap<String, String>) -> bool {
    match params.get("expired") {
        Some(value) if value.is_empty() => true,
        Some(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        ),
        None => false,
    }
}

fn text_response(status: StatusCode, body: impl Into<String>) -> warp::reply::Response {
    warp::reply::with_status(body.into(), status).into_response()
}

fn json_response(status: StatusCode, value: serde_json::Value) -> warp::reply::Response {
    warp::reply::with_status(warp::reply::json(&value), status).into_response()
}

fn json_error_response(status: StatusCode, message: impl Into<String>) -> warp::reply::Response {
    json_response(status, json!({ "error": message.into() }))
}

fn with_state(state: AppState) -> impl Filter<Extract = (AppState,), Error = Infallible> + Clone {
    warp::any().map(move || state.clone())
}

fn extract_username(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }

    let parsed: Result<AuthRequest, _> = serde_json::from_slice(body);
    parsed
        .ok()
        .and_then(|request| request.username)
        .map(|username| username.trim().to_string())
        .filter(|username| !username.is_empty())
}

fn fetch_user_id_by_username(db_path: &str, username: &str) -> Result<Option<i64>, String> {
    let conn = open_connection(db_path)?;
    let mut stmt = with_context(
        conn.prepare("SELECT id FROM users WHERE username = ?1"),
        "failed to prepare user lookup",
    )?;

    let mut rows = with_context(stmt.query([username]), "failed to execute user lookup")?;
    match with_context(rows.next(), "failed to iterate user lookup")? {
        Some(row) => {
            let user_id = with_context(row.get(0), "failed to read user id")?;
            Ok(Some(user_id))
        }
        None => Ok(None),
    }
}

fn update_last_login(db_path: &str, user_id: i64) -> Result<(), String> {
    let conn = open_connection(db_path)?;
    with_context(
        conn.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?1",
            [user_id],
        ),
        "failed to update user last_login",
    )?;
    Ok(())
}

fn log_auth_request(db_path: &str, request_ip: &str, user_id: Option<i64>) -> Result<(), String> {
    let conn = open_connection(db_path)?;
    with_context(
        conn.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?1, ?2)",
            params![request_ip, user_id],
        ),
        "failed to insert auth log",
    )?;
    Ok(())
}

fn is_rate_limited(state: &AppState) -> bool {
    match state.rate_limiter.lock() {
        Ok(mut limiter) => !limiter.allow(Instant::now()),
        Err(_) => true,
    }
}

pub fn build_routes(
    state: AppState,
) -> impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone {
    let method_not_allowed =
        warp::any().map(|| text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed"));

    let auth = warp::path("auth").and(
        warp::post()
            .and(warp::query::<HashMap<String, String>>())
            .and(warp::body::bytes())
            .and(warp::addr::remote())
            .and(with_state(state.clone()))
            .map(auth_handler)
            .or(method_not_allowed),
    );

    let register = warp::path("register").and(
        warp::post()
            .and(warp::body::json::<RegisterRequest>())
            .and(with_state(state.clone()))
            .map(register_handler)
            .or(method_not_allowed),
    );

    let jwks = warp::path!(".well-known" / "jwks.json").and(
        warp::get()
            .and(with_state(state))
            .map(jwks_handler)
            .or(method_not_allowed),
    );

    auth.or(register).or(jwks)
}

fn register_handler(payload: RegisterRequest, state: AppState) -> warp::reply::Response {
    match create_user(state.db_path(), payload) {
        Ok(password) => json_response(StatusCode::CREATED, json!(RegisterResponse { password })),
        Err((status, message)) => json_error_response(status, message),
    }
}

fn auth_handler(
    params: HashMap<String, String>,
    body: bytes::Bytes,
    remote: Option<SocketAddr>,
    state: AppState,
) -> warp::reply::Response {
    if is_rate_limited(&state) {
        return text_response(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests");
    }

    let use_expired_key = should_use_expired_key(&params);
    let now = Utc::now().timestamp();

    let signing_key = match load_signing_key(state.db_path(), use_expired_key) {
        Ok(key) => key,
        Err(err) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format_error("failed to load signing key", err),
            );
        }
    };

    let mut header = Header::new(JwtAlgorithm::RS256);
    header.kid = Some(signing_key.kid.to_string());

    let key_text = match String::from_utf8(signing_key.key_pem) {
        Ok(text) => text,
        Err(err) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format_error("stored signing key was not valid UTF-8", err),
            );
        }
    };

    let encoding_key = match EncodingKey::from_rsa_pem(key_text.as_bytes()) {
        Ok(key) => key,
        Err(err) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format_error("stored signing key was invalid", err),
            );
        }
    };

    let claims = JwtClaims {
        sub: JWT_SUBJECT,
        name: JWT_NAME,
        iat: now,
        exp: if use_expired_key {
            now - KEY_LIFETIME_SECONDS
        } else {
            now + KEY_LIFETIME_SECONDS
        },
    };

    let token = match jwt_encode(&header, &claims, &encoding_key) {
        Ok(token) => token,
        Err(err) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format_error("failed to sign JWT", err),
            );
        }
    };

    let username = extract_username(body.as_ref());
    let user_id = match username {
        Some(ref username) => {
            fetch_user_id_by_username(state.db_path(), username).unwrap_or_default()
        }
        None => None,
    };

    if let Some(id) = user_id {
        let _ = update_last_login(state.db_path(), id);
    }

    let ip = remote
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let _ = log_auth_request(state.db_path(), &ip, user_id);

    text_response(StatusCode::OK, token)
}

fn jwks_handler(state: AppState) -> warp::reply::Response {
    let private_keys = match load_valid_private_keys(state.db_path()) {
        Ok(keys) => keys,
        Err(err) => {
            return json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format_error("failed to load keys", err),
            );
        }
    };

    let mut keys = Vec::new();
    let mut malformed_key_count = 0;

    for private_key in private_keys {
        let key_text = match String::from_utf8(private_key.key_pem) {
            Ok(text) => text,
            Err(_) => {
                malformed_key_count += 1;
                continue;
            }
        };

        let parsed_private = match RsaPrivateKey::from_pkcs1_pem(&key_text) {
            Ok(key) => key,
            Err(_) => {
                malformed_key_count += 1;
                continue;
            }
        };

        let public_key = RsaPublicKey::from(&parsed_private);
        let modulus = base64_url::encode(&public_key.n().to_bytes_be());
        let exponent = base64_url::encode(&public_key.e().to_bytes_be());

        keys.push(json!({
            "kty": "RSA",
            "kid": private_key.kid.to_string(),
            "use": "sig",
            "n": modulus,
            "e": exponent,
            "alg": "RS256"
        }));
    }

    if keys.is_empty() && malformed_key_count > 0 {
        return json_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to convert valid keys to JWKS",
        );
    }

    json_response(StatusCode::OK, json!({ "keys": keys }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;
    use warp::test::request;

    fn setup_state() -> (AppState, TempDir) {
        std::env::set_var(ENCRYPTION_ENV, "unit-test-encryption-key");

        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("lib_unit_test.db");
        let db_path_str = db_path.to_str().expect("invalid db path");

        initialize_database(db_path_str).expect("failed to initialize db");
        (AppState::new(db_path_str.to_string()), temp_dir)
    }

    #[test]
    fn initialize_database_is_idempotent() {
        std::env::set_var(ENCRYPTION_ENV, "unit-test-encryption-key");

        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("idempotent_seed.db");
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

    #[tokio::test]
    async fn auth_and_jwks_return_ok_for_seeded_database() {
        let (state, _temp_dir) = setup_state();
        let routes = build_routes(state);

        let auth_response = request().method("POST").path("/auth").reply(&routes).await;
        assert_eq!(auth_response.status(), StatusCode::OK);

        let jwks_response = request()
            .method("GET")
            .path("/.well-known/jwks.json")
            .reply(&routes)
            .await;
        assert_eq!(jwks_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_returns_500_for_missing_database_path() {
        std::env::set_var(ENCRYPTION_ENV, "unit-test-encryption-key");

        let routes = build_routes(AppState::new(
            "this/path/does/not/exist/lib_auth_missing.db",
        ));
        let response = request().method("POST").path("/auth").reply(&routes).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn register_creates_user_and_returns_generated_password() {
        let (state, _temp_dir) = setup_state();
        let routes = build_routes(state.clone());

        let response = request()
            .method("POST")
            .path("/register")
            .header("content-type", "application/json")
            .body("{\"username\":\"new-user\",\"email\":\"new@example.com\"}")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);

        let parsed: serde_json::Value =
            serde_json::from_slice(response.body()).expect("invalid response json");
        let password = parsed["password"]
            .as_str()
            .expect("password was missing from response");

        assert!(!password.is_empty());

        let conn = Connection::open(state.db_path()).expect("failed to open db");
        let user_count: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM users WHERE username = 'new-user'",
                [],
                |row| row.get(0),
            )
            .expect("failed to query user count");
        assert_eq!(user_count, 1);
    }
}
