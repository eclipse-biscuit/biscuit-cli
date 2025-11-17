/*
 * SPDX-FileCopyrightText: 2025 David Legrand <me@davlgd.fr>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! Integration tests for keypair generation and manipulation.
//!
//! These tests verify that:
//! - Random keypair generation works correctly
//! - Keypair can be derived from existing private keys
//! - Different output formats (hex, PEM) work correctly
//! - Individual key export (public-only, private-only) works

mod common;

use predicates::prelude::*;

/// Test that generating a new random keypair works and outputs valid keys
#[test]
fn test_generate_random_keypair() {
    let output = common::biscuit_cmd()
        .arg("keypair")
        .assert()
        .success()
        .stdout(predicate::str::contains("Generating a new random keypair"))
        .stdout(predicate::str::contains("Private key:"))
        .stdout(predicate::str::contains("Public key:"));

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Extract and verify keys using helper functions
    let private_key = common::extract_key_from_output(&stdout, "Private key:")
        .expect("No private key in output");
    let public_key = common::extract_key_from_output(&stdout, "Public key:")
        .expect("No public key in output");

    // Verify format is valid
    assert!(common::verify_key_format(&private_key), "Invalid private key format");
    assert!(common::verify_key_format(&public_key), "Invalid public key format");

    // Verify private key contains "private" in algorithm name
    assert!(private_key.contains("-private") || private_key.contains("private"),
        "Private key should contain 'private' in algorithm name");
}

/// Test that generating a keypair from an existing private key works (both --from-private-key and --from-file)
#[test]
fn test_generate_keypair_from_existing_key() {
    // Generate initial keypair
    let output = common::biscuit_cmd()
        .arg("keypair")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    let private_key = common::extract_key_from_output(&stdout, "Private key:")
        .expect("No private key in output");

    // Test 1: Generate from private key string
    let output_from_string = common::biscuit_cmd()
        .arg("keypair")
        .arg("--from-private-key")
        .arg(&private_key)
        .assert()
        .success();

    let stdout_from_string = String::from_utf8_lossy(&output_from_string.get_output().stdout);
    assert!(stdout_from_string.contains(&private_key), "Regenerated keypair should contain same private key");
    assert!(stdout_from_string.contains("Generating a keypair from the provided private key"));

    // Test 2: Generate from file
    let dir = common::temp_dir();
    let key_file = dir.path().join("private.key");
    std::fs::write(&key_file, &private_key).expect("Failed to write key file");

    let output_from_file = common::biscuit_cmd()
        .arg("keypair")
        .arg("--from-file")
        .arg(&key_file)
        .assert()
        .success();

    let stdout_from_file = String::from_utf8_lossy(&output_from_file.get_output().stdout);
    assert!(stdout_from_file.contains(&private_key), "Keypair from file should contain same private key");
}

/// Test that exporting only public or private keys works
#[test]
fn test_export_single_key() {
    // Test public key only
    let output_pub = common::biscuit_cmd()
        .arg("keypair")
        .arg("--only-public-key")
        .assert()
        .success();

    let public_key = String::from_utf8_lossy(&output_pub.get_output().stdout).trim().to_string();
    assert!(common::verify_key_format(&public_key), "Invalid public key format");
    assert!(!public_key.contains("Private"), "Public key output should not contain 'Private' label");
    assert!(!public_key.contains("private"), "Public key should not contain 'private' in algorithm");

    // Test private key only
    let output_priv = common::biscuit_cmd()
        .arg("keypair")
        .arg("--only-private-key")
        .assert()
        .success();

    let private_key = String::from_utf8_lossy(&output_priv.get_output().stdout).trim().to_string();
    assert!(common::verify_key_format(&private_key), "Invalid private key format");
    assert!(private_key.contains("-private") || private_key.contains("private"),
        "Private key should contain 'private' in algorithm name");
}

/// Test PEM output format for keypairs
#[test]
fn test_keypair_pem_format() {
    let mut cmd = common::biscuit_cmd();
    cmd.arg("keypair")
        .arg("--key-output-format")
        .arg("pem")
        .assert()
        .success()
        .stdout(predicate::str::contains("-----BEGIN PRIVATE KEY-----"))
        .stdout(predicate::str::contains("-----END PRIVATE KEY-----"))
        .stdout(predicate::str::contains("-----BEGIN PUBLIC KEY-----"))
        .stdout(predicate::str::contains("-----END PUBLIC KEY-----"));
}

/// Test that attempting to use conflicting options fails
#[test]
fn test_keypair_conflicting_options() {
    // Can't specify both --from-private-key and --from-file
    common::biscuit_cmd()
        .arg("keypair")
        .arg("--from-private-key")
        .arg("abc123")
        .arg("--from-file")
        .arg("test.key")
        .assert()
        .failure();
}

/// Test different key algorithms (Ed25519 and secp256r1)
#[test]
fn test_keypair_algorithms() {
    for algorithm in &["ed25519", "secp256r1"] {
        let output = common::biscuit_cmd()
            .arg("keypair")
            .arg("--key-algorithm")
            .arg(algorithm)
            .assert()
            .success();

        let stdout = String::from_utf8_lossy(&output.get_output().stdout);

        // Verify output contains keys and correct algorithm
        assert!(stdout.contains("Private key:"), "Missing 'Private key:' for {}", algorithm);
        assert!(stdout.contains("Public key:"), "Missing 'Public key:' for {}", algorithm);
        assert!(stdout.contains(algorithm), "Output should contain algorithm name '{}'", algorithm);

        // Verify keys are valid
        let private_key = common::extract_key_from_output(&stdout, "Private key:")
            .expect(&format!("No private key for {} algorithm", algorithm));
        let public_key = common::extract_key_from_output(&stdout, "Public key:")
            .expect(&format!("No public key for {} algorithm", algorithm));

        assert!(common::verify_key_format(&private_key),
            "Invalid private key format for {} algorithm", algorithm);
        assert!(common::verify_key_format(&public_key),
            "Invalid public key format for {} algorithm", algorithm);
    }
}
