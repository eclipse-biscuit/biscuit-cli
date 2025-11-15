/*
 * SPDX-FileCopyrightText: 2025 David Legrand <me@davlgd.fr>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! Common test utilities and fixtures for biscuit-cli integration tests.
//!
//! This module provides helper functions to make integration tests easier to write
//! and understand. It includes utilities for:
//! - Creating temporary directories and files
//! - Generating test keypairs and tokens
//! - Running the CLI with common patterns
//! - Asserting on command outputs

use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

// Common test values to avoid magic numbers/strings
#[allow(dead_code)]
pub const TEST_USER_ID: &str = "1234";
#[allow(dead_code)]
pub const TEST_RESOURCE: &str = "/api/users";
#[allow(dead_code)]
pub const TEST_OPERATION: &str = "read";

/// Creates a new Command instance for the biscuit CLI binary
#[allow(deprecated)]
pub fn biscuit_cmd() -> Command {
    Command::cargo_bin("biscuit").expect("Failed to find biscuit binary")
}

/// Helper to create a temporary directory for test files.
/// The directory will be automatically cleaned up when the TempDir is dropped.
#[allow(dead_code)]
pub fn temp_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

/// Extract a key from keypair command output.
/// Looks for lines starting with the given label (e.g., "Private key:" or "Public key:")
/// and returns the trimmed key value.
#[allow(dead_code)]
pub fn extract_key_from_output(output: &str, label: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.starts_with(label))?
        .splitn(2, ':')
        .nth(1)
        .map(|s| s.trim().to_string())
}

/// Verify that a key string has the expected format: algorithm/hex
/// Returns true if the format is valid.
#[allow(dead_code)]
pub fn verify_key_format(key: &str) -> bool {
    let parts: Vec<&str> = key.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    // Verify hex part
    parts[1].chars().all(|c| c.is_ascii_hexdigit())
}

/// Generate a test keypair and return paths to the private and public key files.
/// Returns (temp_dir, private_key_path, public_key_path, private_key_content, public_key_content)
pub fn generate_test_keypair() -> (TempDir, PathBuf, PathBuf, String, String) {
    let dir = temp_dir();
    let private_key_path = dir.path().join("private_key.txt");
    let public_key_path = dir.path().join("public_key.txt");

    // Generate keypair using the CLI
    let output = biscuit_cmd()
        .arg("keypair")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Extract keys using helper function
    let private_key = extract_key_from_output(&stdout, "Private key:")
        .expect("No private key in keypair output");
    let public_key = extract_key_from_output(&stdout, "Public key:")
        .expect("No public key in keypair output");

    // Write keys to files
    std::fs::write(&private_key_path, &private_key).expect("Failed to write private key");
    std::fs::write(&public_key_path, &public_key).expect("Failed to write public key");

    (dir, private_key_path, public_key_path, private_key, public_key)
}

/// Generate a basic test token with a simple authority block.
/// Returns (temp_dir, token_path, private_key, public_key)
#[allow(dead_code)]
pub fn generate_test_token() -> (TempDir, PathBuf, String, String) {
    let (dir, private_key_path, _public_key_path, private_key, public_key) = generate_test_keypair();
    let token_path = dir.path().join("token.biscuit");

    // Generate a simple token with basic authority facts
    // Note: datalog is passed as stdin using "-", output goes to stdout
    let datalog = format!("user({});", TEST_USER_ID);
    let output = biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("-")
        .write_stdin(datalog.as_bytes())
        .assert()
        .success();

    // Write stdout to file
    std::fs::write(&token_path, &output.get_output().stdout).expect("Failed to write token file");

    (dir, token_path, private_key, public_key)
}

/// Generate a test token with specific datalog content.
/// Returns (temp_dir, token_path, private_key, public_key)
#[allow(dead_code)]
pub fn generate_test_token_with_content(datalog: &str) -> (TempDir, PathBuf, String, String) {
    let (dir, private_key_path, _public_key_path, private_key, public_key) = generate_test_keypair();
    let token_path = dir.path().join("token.biscuit");

    let output = biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("-")
        .write_stdin(datalog)
        .assert()
        .success();

    // Write stdout to file
    std::fs::write(&token_path, &output.get_output().stdout).expect("Failed to write token file");

    (dir, token_path, private_key, public_key)
}

// Note: We don't test the helper functions themselves here.
// They are indirectly tested by all the integration tests that use them.
// This avoids redundancy and keeps the test suite focused on actual CLI functionality.
