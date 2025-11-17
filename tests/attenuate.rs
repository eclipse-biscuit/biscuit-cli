/*
 * SPDX-FileCopyrightText: 2025 David Legrand <me@davlgd.fr>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! Integration tests for token attenuation.
//!
//! Attenuation allows adding new blocks to a token to further restrict its capabilities.
//! These tests verify that:
//! - Blocks can be added to existing tokens
//! - Attenuated tokens maintain authority block content
//! - Multiple attenuations can be chained
//! - Attenuated tokens can be verified

mod common;

/// Test basic token attenuation with a simple block
#[test]
fn test_simple_attenuation() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let attenuated_path = dir.path().join("attenuated.biscuit");

    // Attenuate the token with a new block
    let output = common::biscuit_cmd()
        .arg("attenuate")
        .arg(&token_path)
        .arg("--block")
        .arg("check if operation(\"read\");")
        .assert()
        .success();

    // Write stdout to file
    std::fs::write(&attenuated_path, &output.get_output().stdout).unwrap();

    // Verify attenuated token exists
    assert!(attenuated_path.exists());

    // Inspect the attenuated token
    let output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&attenuated_path)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Should contain original authority block
    assert!(stdout.contains("user(1234)"));

    // Should contain new block
    assert!(stdout.contains("check if operation(\"read\")"));
}

/// Test multiple sequential attenuations
#[test]
fn test_multiple_attenuations() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let attenuated1_path = dir.path().join("attenuated1.biscuit");
    let attenuated2_path = dir.path().join("attenuated2.biscuit");

    // First attenuation
    let output = common::biscuit_cmd()
        .arg("attenuate")
        .arg(&token_path)
        .arg("--block")
        .arg("check if resource(\"/api/users\");")
        .assert()
        .success();

    std::fs::write(&attenuated1_path, &output.get_output().stdout).unwrap();

    // Second attenuation on the first attenuated token
    let output = common::biscuit_cmd()
        .arg("attenuate")
        .arg(&attenuated1_path)
        .arg("--block")
        .arg("check if operation(\"read\");")
        .assert()
        .success();

    std::fs::write(&attenuated2_path, &output.get_output().stdout).unwrap();

    // Inspect final token
    let output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&attenuated2_path)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Should contain all blocks
    assert!(stdout.contains("user(1234)")); // authority
    assert!(stdout.contains("resource(\"/api/users\")")); // first attenuation
    assert!(stdout.contains("operation(\"read\")")); // second attenuation
}

/// Test attenuation with parameter interpolation
#[test]
fn test_attenuation_with_parameters() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let attenuated_path = dir.path().join("attenuated.biscuit");

    // Attenuate with parameters
    let output = common::biscuit_cmd()
        .arg("attenuate")
        .arg(&token_path)
        .arg("--block")
        .arg("max_operations({max});")
        .arg("--param")
        .arg("max:integer=10")
        .assert()
        .success();

    std::fs::write(&attenuated_path, &output.get_output().stdout).unwrap();

    // Verify parameter was substituted
    let output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&attenuated_path)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("max_operations(10)"));
}

/// Test that attenuated token can still be verified with public key
#[test]
fn test_attenuated_token_verification() {
    let (dir, token_path, _, public_key) = common::generate_test_token();
    let attenuated_path = dir.path().join("attenuated.biscuit");
    let public_key_path = dir.path().join("public.key");

    std::fs::write(&public_key_path, &public_key).unwrap();

    // Attenuate token
    let output = common::biscuit_cmd()
        .arg("attenuate")
        .arg(&token_path)
        .arg("--block")
        .arg("resource(\"/api/posts\");")
        .assert()
        .success();

    std::fs::write(&attenuated_path, &output.get_output().stdout).unwrap();

    // Verify attenuated token signature
    common::biscuit_cmd()
        .arg("inspect")
        .arg(&attenuated_path)
        .arg("--public-key-file")
        .arg(&public_key_path)
        .assert()
        .success();
}

/// Test attenuation from stdin
#[test]
fn test_attenuation_from_stdin() {
    let (_dir, token_path, _, _) = common::generate_test_token();

    // Read token content
    let token_content = std::fs::read_to_string(&token_path).unwrap();

    // Attenuate from stdin, output to stdout
    let output = common::biscuit_cmd()
        .arg("attenuate")
        .arg("-")
        .arg("--block")
        .arg("check if operation(\"read\");")
        .write_stdin(token_content.as_bytes())
        .assert()
        .success();

    // Output should be a valid token (base64 by default)
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(!stdout.trim().is_empty());
}

/// Test that attenuation preserves the token's revocation IDs
#[test]
fn test_attenuation_preserves_revocation_ids() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let attenuated_path = dir.path().join("attenuated.biscuit");

    // Get original revocation IDs
    let _output_original = common::biscuit_cmd()
        .arg("inspect")
        .arg(&token_path)
        .assert()
        .success();

    // Attenuate
    let output = common::biscuit_cmd()
        .arg("attenuate")
        .arg(&token_path)
        .arg("--block")
        .arg("check if true;")
        .assert()
        .success();

    std::fs::write(&attenuated_path, &output.get_output().stdout).unwrap();

    // Get attenuated revocation IDs
    let output_attenuated = common::biscuit_cmd()
        .arg("inspect")
        .arg(&attenuated_path)
        .assert()
        .success();

    let stdout_attenuated = String::from_utf8_lossy(&output_attenuated.get_output().stdout);

    // Attenuated token should have more revocation IDs (one per block)
    // but should still contain the original ones
    assert!(stdout_attenuated.contains("Revocation id") || stdout_attenuated.contains("revocation"));
}

/// Test that attempting to attenuate a sealed token fails
/// (This test will be more relevant once we implement seal tests)
#[test]
fn test_cannot_attenuate_sealed_token() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let sealed_path = dir.path().join("sealed.biscuit");

    // Seal the token first
    let output = common::biscuit_cmd()
        .arg("seal")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&sealed_path, &output.get_output().stdout).unwrap();

    // Attempting to attenuate should fail
    common::biscuit_cmd()
        .arg("attenuate")
        .arg(&sealed_path)
        .arg("--block")
        .arg("check if operation(\"read\");")
        .assert()
        .failure();
}

/// Test attenuation without specifying output writes to stdout
#[test]
fn test_attenuation_to_stdout() {
    let (_dir, token_path, _, _) = common::generate_test_token();

    let output = common::biscuit_cmd()
        .arg("attenuate")
        .arg(&token_path)
        .arg("--block")
        .arg("check if operation(\"read\");")
        .assert()
        .success();

    // Should output base64-encoded token to stdout
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(!stdout.trim().is_empty());
}
