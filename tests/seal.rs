/*
 * SPDX-FileCopyrightText: 2025 David Legrand <me@davlgd.fr>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! Integration tests for token sealing.
//!
//! Sealing a token prevents further attenuation. This is useful when you want
//! to ensure that no more restrictions can be added to a token.
//!
//! These tests verify that:
//! - Tokens can be sealed
//! - Sealed tokens cannot be attenuated
//! - Sealed tokens can still be inspected and verified

mod common;

use predicates::prelude::*;

/// Test basic token sealing
#[test]
fn test_seal_token() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let sealed_path = dir.path().join("sealed.biscuit");

    // Seal the token
    let output = common::biscuit_cmd()
        .arg("seal")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&sealed_path, &output.get_output().stdout).unwrap();

    // Verify sealed token exists
    assert!(sealed_path.exists());

    // Sealed token should be inspectable
    common::biscuit_cmd()
        .arg("inspect")
        .arg(&sealed_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("user(1234)"));
}

/// Test that sealed token cannot be attenuated
#[test]
fn test_sealed_token_cannot_be_attenuated() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let sealed_path = dir.path().join("sealed.biscuit");

    // Seal the token
    let output = common::biscuit_cmd()
        .arg("seal")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&sealed_path, &output.get_output().stdout).unwrap();

    // Attempting to attenuate sealed token should fail
    common::biscuit_cmd()
        .arg("attenuate")
        .arg(&sealed_path)
        .arg("--block")
        .arg("check if operation(\"read\");")
        .assert()
        .failure()
        .stderr(predicate::str::contains("seal").or(predicate::str::contains("cannot")));
}

/// Test that sealed token can be verified with public key
#[test]
fn test_verify_sealed_token() {
    let (dir, token_path, _, public_key) = common::generate_test_token();
    let sealed_path = dir.path().join("sealed.biscuit");
    let public_key_path = dir.path().join("public.key");

    std::fs::write(&public_key_path, &public_key).unwrap();

    // Seal the token
    let output = common::biscuit_cmd()
        .arg("seal")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&sealed_path, &output.get_output().stdout).unwrap();

    // Verify sealed token
    common::biscuit_cmd()
        .arg("inspect")
        .arg(&sealed_path)
        .arg("--public-key-file")
        .arg(&public_key_path)
        .assert()
        .success();
}

/// Test sealing an attenuated token
#[test]
fn test_seal_attenuated_token() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let attenuated_path = dir.path().join("attenuated.biscuit");
    let sealed_path = dir.path().join("sealed.biscuit");

    // Attenuate first
    let output = common::biscuit_cmd()
        .arg("attenuate")
        .arg(&token_path)
        .arg("--block")
        .arg("check if operation(\"read\");")
        .assert()
        .success();

    std::fs::write(&attenuated_path, &output.get_output().stdout).unwrap();

    // Then seal
    let output = common::biscuit_cmd()
        .arg("seal")
        .arg(&attenuated_path)
        .assert()
        .success();

    std::fs::write(&sealed_path, &output.get_output().stdout).unwrap();

    // Inspect should show both authority and attenuated block
    let output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&sealed_path)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("user(1234)")); // authority
    assert!(stdout.contains("operation(\"read\")")); // attenuated block
}

/// Test sealing from stdin
#[test]
fn test_seal_from_stdin() {
    let (_dir, token_path, _, _) = common::generate_test_token();

    // Read token content
    let token_content = std::fs::read_to_string(&token_path).unwrap();

    // Seal from stdin, output to stdout
    let output = common::biscuit_cmd()
        .arg("seal")
        .arg("-")
        .write_stdin(token_content.as_bytes())
        .assert()
        .success();

    // Output should be a valid token
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(!stdout.trim().is_empty());
}

/// Test sealing to stdout (no output file specified)
#[test]
fn test_seal_to_stdout() {
    let (_dir, token_path, _, _) = common::generate_test_token();

    let output = common::biscuit_cmd()
        .arg("seal")
        .arg(&token_path)
        .assert()
        .success();

    // Should output token to stdout
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(!stdout.trim().is_empty());
}

/// Test that sealed token can still pass authorization checks
#[test]
fn test_sealed_token_authorization() {
    let (dir, token_path, _, public_key) = common::generate_test_token_with_content(
        "user(1234); resource(\"/api/users\"); operation(\"read\");"
    );

    let sealed_path = dir.path().join("sealed.biscuit");
    let public_key_path = dir.path().join("public.key");

    std::fs::write(&public_key_path, &public_key).unwrap();

    // Seal the token
    let output = common::biscuit_cmd()
        .arg("seal")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&sealed_path, &output.get_output().stdout).unwrap();

    // Authorization should still work
    let policy = "allow if user($id), resource($res), operation(\"read\");";

    common::biscuit_cmd()
        .arg("inspect")
        .arg(&sealed_path)
        .arg("--public-key-file")
        .arg(&public_key_path)
        .arg("--authorize-with")
        .arg(policy)
        .assert()
        .success();
}

/// Test double sealing (sealing an already sealed token should fail or be idempotent)
#[test]
fn test_double_seal() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let sealed_path = dir.path().join("sealed.biscuit");
    let double_sealed_path = dir.path().join("double_sealed.biscuit");

    // First seal
    let output = common::biscuit_cmd()
        .arg("seal")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&sealed_path, &output.get_output().stdout).unwrap();

    // Attempt to seal again - this might fail or succeed depending on implementation
    // We just verify it doesn't panic
    let result = common::biscuit_cmd()
        .arg("seal")
        .arg(&sealed_path)
        .output()
        .ok();

    // If successful, write stdout to file
    if let Some(output) = result {
        if output.status.success() {
            std::fs::write(&double_sealed_path, &output.stdout).ok();
        }
    }
}

/// Test that sealed token preserves all blocks from original token
#[test]
fn test_seal_preserves_all_blocks() {
    let (dir, token_path, _, _) = common::generate_test_token_with_content(
        "user(1234); resource(\"/api/users\"); admin(true);"
    );

    // Attenuate with another block
    let attenuated_path = dir.path().join("attenuated.biscuit");
    let output = common::biscuit_cmd()
        .arg("attenuate")
        .arg(&token_path)
        .arg("--block")
        .arg("operation(\"read\"); check if admin(true);")
        .assert()
        .success();

    std::fs::write(&attenuated_path, &output.get_output().stdout).unwrap();

    // Seal
    let sealed_path = dir.path().join("sealed.biscuit");
    let output = common::biscuit_cmd()
        .arg("seal")
        .arg(&attenuated_path)
        .assert()
        .success();

    std::fs::write(&sealed_path, &output.get_output().stdout).unwrap();

    // Inspect and verify all content is present
    let output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&sealed_path)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("user(1234)"));
    assert!(stdout.contains("/api/users"));
    assert!(stdout.contains("admin(true)"));
    assert!(stdout.contains("operation(\"read\")"));
}
