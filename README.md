# JWKS_Project2

This is the repository for Project 2: Extending the JWKS server for CSCE 3550: Spring 2026.

# Overview

This project implements a JWKS server backed by SQLite for persistent RSA private key storage.

- Database file: `totally_not_my_privateKeys.db`
- Table schema:

```sql
CREATE TABLE IF NOT EXISTS keys(
	kid INTEGER PRIMARY KEY AUTOINCREMENT,
	key BLOB NOT NULL,
	exp INTEGER NOT NULL
)
```

# Running

```bash
cargo run
```

Server listens on `127.0.0.1:8080`.

# Testing

```bash
cargo test
```

The test suite covers:

- database initialization and key seeding
- JWT issuance for valid and expired key paths
- JWKS output containing only valid keys
- method handling on endpoints

# Test Coverage

- You can generate coverage with `cargo llvm-cov --workspace --all-features --summary-only`.
