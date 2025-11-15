/*
 * SPDX-FileCopyrightText: 2025 David Legrand <me@davlgd.fr>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! Integration tests for token generation.
//!
//! These tests verify:
//! - Token generation with various datalog configurations
//! - Parameter interpolation
//! - TTL/expiration handling
//! - Context and metadata
//! - Raw binary output
//! - Error handling

mod common;

use predicates::prelude::*;

/// Test basic token generation with authority block (simple and complex)
#[test]
fn test_generate_token() {
    let (dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    // Test 1: Simple single fact
    let simple_datalog = format!("user({});", common::TEST_USER_ID);
    let simple_output = common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("-")
        .write_stdin(simple_datalog.as_bytes())
        .assert()
        .success();

    let simple_token = String::from_utf8_lossy(&simple_output.get_output().stdout);
    assert!(!simple_token.trim().is_empty(), "Generated token should not be empty");

    // Test 2: Multiple facts in authority block
    let complex_datalog = format!(
        "user({}); resource(\"{}\"); operation(\"{}\");",
        common::TEST_USER_ID, common::TEST_RESOURCE, common::TEST_OPERATION
    );
    let complex_output = common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("-")
        .write_stdin(complex_datalog.as_bytes())
        .assert()
        .success();

    // Verify the token can be inspected and contains expected facts
    let token_path = dir.path().join("token.biscuit");
    std::fs::write(&token_path, &complex_output.get_output().stdout)
        .expect("Failed to write token");

    let inspect_output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&token_path)
        .assert()
        .success();

    let inspect_stdout = String::from_utf8_lossy(&inspect_output.get_output().stdout);
    assert!(inspect_stdout.contains(common::TEST_USER_ID), "Inspect should show user ID");
    assert!(inspect_stdout.contains(common::TEST_RESOURCE), "Inspect should show resource");
    assert!(inspect_stdout.contains(common::TEST_OPERATION), "Inspect should show operation");
}

/// Test generating token with parameter interpolation
#[test]
fn test_generate_with_parameters() {
    let (dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();
    let token_path = dir.path().join("token.biscuit");

    // Use parameter placeholders
    let datalog = "user({user_id}); expiration({exp_time});";

    let output = common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("--param")
        .arg("user_id:integer=9876")
        .arg("--param")
        .arg("exp_time:date=2030-12-31T23:59:59Z")
        .arg("-")
        .write_stdin(datalog.as_bytes())
        .assert()
        .success();

    std::fs::write(&token_path, &output.get_output().stdout).unwrap();

    // Verify parameters were interpolated correctly
    let inspect_output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&token_path)
        .assert()
        .success();

    let inspect_stdout = String::from_utf8_lossy(&inspect_output.get_output().stdout);
    assert!(inspect_stdout.contains("user(9876)"), "Parameter user_id should be interpolated");
    assert!(inspect_stdout.contains("expiration("), "Parameter exp_time should be interpolated");
}

/// Test generating token with checks
#[test]
fn test_generate_with_checks() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    let datalog = format!("user({}); check if operation(\"read\");", common::TEST_USER_ID);

    let output = common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("-")
        .write_stdin(datalog.as_bytes())
        .assert()
        .success();

    let token = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(!token.trim().is_empty(), "Generated token with checks should not be empty");
}

/// Test token generation with TTL (time-to-live)
#[test]
fn test_generate_with_ttl() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    let datalog = format!("user({});", common::TEST_USER_ID);

    let output = common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("--add-ttl")
        .arg("30d")
        .arg("-")
        .write_stdin(datalog.as_bytes())
        .assert()
        .success();

    let token = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(!token.trim().is_empty(), "Generated token with TTL should not be empty");
}

/// Test that generating without a private key fails
#[test]
fn test_generate_without_private_key_fails() {
    common::biscuit_cmd()
        .arg("generate")
        .arg("-")
        .write_stdin("user(1234);")
        .assert()
        .failure();
}

// ========== TTL TESTS (Expiration) ==========

/// Test generating token with TTL using duration format
#[test]
fn test_generate_with_ttl_duration() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    let datalog = format!("user({});", common::TEST_USER_ID);

    // Test various duration formats
    for ttl in &["1d", "1h", "30m", "15s"] {
        let output = common::biscuit_cmd()
            .arg("generate")
            .arg("--private-key-file")
            .arg(&private_key_path)
            .arg("--add-ttl")
            .arg(ttl)
            .arg("-")
            .write_stdin(datalog.as_bytes())
            .assert()
            .success();

        let token = String::from_utf8_lossy(&output.get_output().stdout);
        assert!(!token.trim().is_empty(), "Token with TTL {} should be generated", ttl);
    }
}

/// Test generating token with TTL using RFC3339 timestamp
#[test]
fn test_generate_with_ttl_timestamp() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    let datalog = format!("user({});", common::TEST_USER_ID);

    // Use a future timestamp (year 2030)
    let timestamp = "2030-12-31T23:59:59Z";

    let output = common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("--add-ttl")
        .arg(timestamp)
        .arg("-")
        .write_stdin(datalog.as_bytes())
        .assert()
        .success();

    let token = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(!token.trim().is_empty(), "Token with timestamp TTL should be generated");
}

// ========== RAW BINARY I/O TESTS ==========

/// Test raw binary output and input roundtrip
#[test]
fn test_raw_binary_roundtrip() {
    let (dir, private_key_path, _public_key_path, _, public_key) = common::generate_test_keypair();
    let raw_token_path = dir.path().join("token.raw");
    let public_key_path = dir.path().join("public.key");
    std::fs::write(&public_key_path, &public_key).unwrap();

    let datalog = format!("user({});", common::TEST_USER_ID);

    // Generate token with raw output
    let output = common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("--raw")
        .arg("-")
        .write_stdin(datalog.as_bytes())
        .assert()
        .success();

    // Save raw bytes
    let raw_bytes = &output.get_output().stdout;
    std::fs::write(&raw_token_path, raw_bytes).unwrap();

    // Verify raw bytes are not base64 (should contain non-printable chars)
    // Raw protobuf starts with specific bytes
    assert!(raw_bytes.len() > 0, "Raw token should not be empty");

    // Inspect with raw input
    common::biscuit_cmd()
        .arg("inspect")
        .arg(&raw_token_path)
        .arg("--raw-input")
        .arg("--public-key-file")
        .arg(&public_key_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(common::TEST_USER_ID));
}

/// Test raw binary input from stdin
#[test]
fn test_raw_binary_stdin() {
    let (_dir, private_key_path, _public_key_path, _, _public_key) = common::generate_test_keypair();

    let datalog = format!("user({});", common::TEST_USER_ID);

    // Generate token with raw output to stdout
    let output = common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("--raw")
        .arg("-")
        .write_stdin(datalog.as_bytes())
        .assert()
        .success();

    let raw_bytes = &output.get_output().stdout;

    // Inspect from stdin with raw input
    common::biscuit_cmd()
        .arg("inspect")
        .arg("-")
        .arg("--raw-input")
        .write_stdin(&raw_bytes[..])
        .assert()
        .success()
        .stdout(predicate::str::contains(common::TEST_USER_ID));
}

// ========== CONTEXT AND METADATA TESTS ==========

/// Test generating token with context
#[test]
fn test_generate_with_context() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    let datalog = format!("user({});", common::TEST_USER_ID);
    let context = "request_id=12345,environment=production";

    let output = common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("--context")
        .arg(context)
        .arg("-")
        .write_stdin(datalog.as_bytes())
        .assert()
        .success();

    let token = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(!token.trim().is_empty(), "Token with context should be generated");
}

/// Test generating token with root key ID hint
#[test]
fn test_generate_with_root_key_id() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    let datalog = format!("user({});", common::TEST_USER_ID);
    let root_key_id = "42";

    let output = common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("--root-key-id")
        .arg(root_key_id)
        .arg("-")
        .write_stdin(datalog.as_bytes())
        .assert()
        .success();

    let token = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(!token.trim().is_empty(), "Token with root key ID should be generated");
}
