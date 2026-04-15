use project1_rust::{build_routes, initialize_database, AppState, DB_FILE};

const DB_PATH_ENV: &str = "JWKS_DB_PATH";
const SKIP_SERVER_ENV: &str = "JWKS_SKIP_SERVER";

fn configured_db_path() -> String {
    std::env::var(DB_PATH_ENV).unwrap_or_else(|_| DB_FILE.to_string())
}

fn initialize_state(db_path: &str) -> Result<AppState, String> {
    initialize_database(db_path)?;
    Ok(AppState::new(db_path.to_string()))
}

#[tokio::main]
async fn main() {
    let db_path = configured_db_path();

    // Initialize SQLite key storage before accepting requests.
    let state = match initialize_state(&db_path) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("failed to initialize SQLite key store: {err}");
            std::process::exit(1);
        }
    };

    // Build DB-backed routes and start the local HTTP server.
    let routes = build_routes(state);

    if std::env::var(SKIP_SERVER_ENV).as_deref() == Ok("1") {
        return;
    }

    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_state_creates_db_file() {
        std::env::set_var("NOT_MY_KEY", "main-test-encryption-key");

        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("main_unit_test.db");
        let db_path_str = db_path.to_str().expect("invalid db path");

        let state = initialize_state(db_path_str).expect("initialize_state should succeed");

        assert_eq!(state.db_path(), db_path_str);
        assert!(db_path.exists(), "database file should exist after init");
    }

    #[test]
    fn initialize_state_errors_for_missing_parent_directory() {
        std::env::set_var("NOT_MY_KEY", "main-test-encryption-key");

        let err = match initialize_state("this/path/does/not/exist/main_unit_test.db") {
            Ok(_) => panic!("initialize_state should fail for missing parent directory"),
            Err(err) => err,
        };

        assert!(
            err.contains("failed to open SQLite database"),
            "unexpected error: {err}"
        );
    }
}
