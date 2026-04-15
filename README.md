# JWKS Project 3

Secure JWKS server in Rust with encrypted private key storage, user registration, authentication request logging, and request rate limiting.

## Security and Feature Summary

- Private keys are stored encrypted in SQLite using AES-256-GCM.
- Encryption/decryption key material is derived from environment variable NOT_MY_KEY.
- Users are stored in a users table with Argon2id hashed passwords.
- POST /register generates a UUIDv4 password and returns it to the client.
- Authentication requests are logged to auth_logs with request IP and user_id (when resolvable by username).
- POST /auth is rate-limited to 10 requests per second and returns HTTP 429 on limit exceed.

## Database Tables

The service creates the following tables at startup:

- keys
- users
- auth_logs

## API Endpoints

### POST /register

Request JSON:

{
  "username": "MyCoolUsername",
  "email": "person@example.com"
}

Response JSON (201 Created):

{
  "password": "<UUIDv4>"
}

### POST /auth

- Issues JWT signed by an RSA private key loaded from encrypted key storage.
- Logs successful requests to auth_logs.
- Enforces rate limit of 10 requests/second.
- Returns 429 Too Many Requests when limited.

### GET /.well-known/jwks.json

Returns current valid public keys in JWKS format.

## Required Environment Variables

- NOT_MY_KEY: secret string used to derive AES key for key-at-rest encryption.

Example:

export NOT_MY_KEY="replace-with-a-strong-secret"

## Local Development

Run server:

cargo run

Server binds to 127.0.0.1:8080.

## Quality Gates

Format:

cargo fmt --check

Lint:

cargo clippy --all-targets --all-features -- -D warnings

Tests:

cargo test

Coverage:

cargo llvm-cov --workspace --all-features --summary-only

Most recent measured coverage in this workspace:

- Regions: 85.31%
- Lines: 83.72%
- Functions: 80.88%

## Project Structure

- src/lib.rs: core routes, crypto, DB setup, handlers, and tests
- src/main.rs: binary entrypoint and startup wiring
- tests/integration_tests.rs: integration tests for endpoints, encryption, logging, and rate limiting
