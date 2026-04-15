use chrono::Utc;
use jsonwebtoken::{encode as jwt_encode, Algorithm, EncodingKey, Header};
use rand::thread_rng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use warp::{http::StatusCode, Filter, Rejection};

/// SQLite filename required by the project rubric.
pub const DB_FILE: &str = "totally_not_my_privateKeys.db";

const TABLE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS keys(\
    kid INTEGER PRIMARY KEY AUTOINCREMENT,\
    key BLOB NOT NULL,\
    exp INTEGER NOT NULL\
)";
const KEY_LIFETIME_SECONDS: i64 = 3600;
const JWT_SUBJECT: &str = "userABC";
const JWT_NAME: &str = "userABC";

/// Shared application state containing the SQLite file path.
#[derive(Clone)]
pub struct AppState {
    db_path: Arc<String>,
}

impl AppState {
    pub fn new(db_path: impl Into<String>) -> Self {
        Self {
            db_path: Arc::new(db_path.into()),
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

#[derive(Serialize)]
struct JwtClaims {
    sub: &'static str,
    name: &'static str,
    iat: i64,
    exp: i64,
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

/// Creates/opens the SQLite database, ensures schema exists, and seeds keys.
pub fn initialize_database(db_path: &str) -> Result<(), String> {
    // Open/create the database, ensure schema exists, and seed required key rows.
    let mut conn = open_connection(db_path)?;

    with_context(conn.execute(TABLE_SCHEMA, []), "failed to create keys table")?;

    ensure_seed_keys(&mut conn)?;
    Ok(())
}

fn ensure_seed_keys(conn: &mut Connection) -> Result<(), String> {
    let now = Utc::now().timestamp();
    let transaction = with_context(conn.transaction(), "failed to start seed transaction")?;

    // Seed one expired key if none currently exist.
    let expired_count = transaction
        .query_row("SELECT COUNT(1) FROM keys WHERE exp <= ?1", [now], |row| {
            row.get(0)
        });
    let expired_count: i64 = with_context(expired_count, "failed to count expired keys")?;

    if expired_count == 0 {
        let expired_pem = generate_private_key_pem()?;
        let expired_exp = now - KEY_LIFETIME_SECONDS;
        with_context(
            transaction.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                params![expired_pem.into_bytes(), expired_exp],
            ),
            "failed to insert expired key",
        )?;
    }

    // Seed one valid key if none currently exist.
    let valid_count = transaction
        .query_row("SELECT COUNT(1) FROM keys WHERE exp > ?1", [now], |row| {
            row.get(0)
        });
    let valid_count: i64 = with_context(valid_count, "failed to count valid keys")?;

    if valid_count == 0 {
        let valid_pem = generate_private_key_pem()?;
        let valid_exp = now + KEY_LIFETIME_SECONDS;
        with_context(
            transaction.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                params![valid_pem.into_bytes(), valid_exp],
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

    // Select an expired or valid signing key based on the request mode.
    let query = if use_expired {
        "SELECT kid, key FROM keys WHERE exp <= ?1 ORDER BY exp DESC LIMIT 1"
    } else {
        "SELECT kid, key FROM keys WHERE exp > ?1 ORDER BY exp ASC LIMIT 1"
    };

    let signing_key = conn.query_row(query, [now], |row| {
        Ok(StoredKey {
            kid: row.get(0)?,
            key_pem: row.get(1)?,
        })
    });
    with_context(signing_key, "failed to load signing key")
}

fn load_valid_private_keys(db_path: &str) -> Result<Vec<StoredKey>, String> {
    // Return all currently valid keys for JWKS publication.
    let conn = open_connection(db_path)?;
    let now = Utc::now().timestamp();

    let mut statement = with_context(
        conn.prepare("SELECT kid, key FROM keys WHERE exp > ?1 ORDER BY kid ASC"),
        "failed to prepare valid-key query",
    )?;

    let rows = statement
        .query_map([now], |row| {
            Ok(StoredKey {
                kid: row.get(0)?,
                key_pem: row.get(1)?,
            })
        });
    let rows = with_context(rows, "failed to execute valid-key query")?;

    let mut keys = Vec::new();
    for row in rows {
        keys.push(with_context(row, "failed to read key row")?);
    }

    Ok(keys)
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

fn text_response(status: StatusCode, body: impl Into<String>) -> warp::reply::WithStatus<String> {
    warp::reply::with_status(body.into(), status)
}

fn json_error_response(
    status: StatusCode,
    message: impl Into<String>,
) -> warp::reply::WithStatus<warp::reply::Json> {
    let body = json!({ "error": message.into() });
    warp::reply::with_status(warp::reply::json(&body), status)
}

fn with_state(state: AppState) -> impl Filter<Extract = (AppState,), Error = Infallible> + Clone {
    warp::any().map(move || state.clone())
}

/// Builds all HTTP routes for the Project 2 JWKS service.
pub fn build_routes(
    state: AppState,
) -> impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone {
    // Shared fallback for unsupported methods on known paths.
    let method_not_allowed =
        warp::any().map(|| text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed"));

    // POST /auth issues JWTs signed by a DB-backed private key.
    let auth = warp::path("auth").and(
        warp::post()
            .and(warp::query::<HashMap<String, String>>())
            .and(with_state(state.clone()))
            .map(auth_handler)
            .or(method_not_allowed),
    );

    // GET /.well-known/jwks.json publishes public keys for valid private keys.
    let jwks = warp::path!(".well-known" / "jwks.json").and(
        warp::get()
            .and(with_state(state))
            .map(jwks_handler)
            .or(method_not_allowed),
    );

    auth.or(jwks)
}

fn auth_handler(
    params: HashMap<String, String>,
    state: AppState,
) -> warp::reply::WithStatus<String> {
    // Resolve whether this request should use an expired or valid signing key.
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

    // Set JWT metadata, including the key id from the database row.
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(signing_key.kid.to_string());

    // Convert stored PEM bytes into an encoding key for signing.
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

    // Build the mock claims expected by the project client.
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

    match jwt_encode(&header, &claims, &encoding_key) {
        Ok(token) => text_response(StatusCode::OK, token),
        Err(err) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format_error("failed to sign JWT", err),
        ),
    }
}

fn jwks_handler(state: AppState) -> warp::reply::WithStatus<warp::reply::Json> {
    // Load all non-expired keys and convert each to a public JWK entry.
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
        // Skip malformed rows so one bad key does not break the full JWKS response.
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

    let jwks = json!({ "keys": keys });
    warp::reply::with_status(warp::reply::json(&jwks), StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};
    use tempfile::TempDir;
    use warp::test::request;

    fn setup_state() -> (AppState, TempDir) {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("lib_unit_test.db");
        let db_path_str = db_path.to_str().expect("invalid db path");

        initialize_database(db_path_str).expect("failed to initialize db");
        (AppState::new(db_path_str.to_string()), temp_dir)
    }

    #[test]
    fn initialize_database_is_idempotent() {
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
        let routes = build_routes(AppState::new("this/path/does/not/exist/lib_auth_missing.db"));
        let response = request().method("POST").path("/auth").reply(&routes).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn jwks_returns_500_for_missing_database_path() {
        let routes = build_routes(AppState::new("this/path/does/not/exist/lib_jwks_missing.db"));
        let response = request()
            .method("GET")
            .path("/.well-known/jwks.json")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn auth_returns_500_for_invalid_utf8_signing_key() {
        let (state, _temp_dir) = setup_state();
        let conn = Connection::open(state.db_path()).expect("failed to open db");
        let now = Utc::now().timestamp();
        conn.execute(
            "UPDATE keys SET key = ?1 WHERE exp > ?2",
            params![vec![0xff_u8, 0xfe_u8, 0xfd_u8], now],
        )
        .expect("failed to update valid key blob");

        let routes = build_routes(state);
        let response = request().method("POST").path("/auth").reply(&routes).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
