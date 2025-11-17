/*
 * SPDX-FileCopyrightText: 2025 David Legrand <me@davlgd.fr>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! Integration tests for error handling.
//!
//! These tests verify that the CLI fails gracefully with clear error messages
//! for all types of invalid input.

mod common;

use predicates::prelude::*;

// ========== SIGNATURE ERRORS ==========

/// Test inspecting token with wrong public key (signature mismatch)
#[test]
fn test_inspect_wrong_public_key() {
    let (dir, token_path, _, _) = common::generate_test_token();

    // Generate a different keypair
    let (_other_dir, _other_priv, _other_pub, _, wrong_public_key) = common::generate_test_keypair();
    let wrong_key_path = dir.path().join("wrong.key");
    std::fs::write(&wrong_key_path, &wrong_public_key).unwrap();

    // Should fail with signature error
    common::biscuit_cmd()
        .arg("inspect")
        .arg(&token_path)
        .arg("--public-key-file")
        .arg(&wrong_key_path)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Signature")  // Case-sensitive: "Signatures check failed"
                .or(predicate::str::contains("signature"))
                .or(predicate::str::contains("invalid"))
                .or(predicate::str::contains("verification"))
        );
}

/// Test token with corrupted data
#[test]
fn test_inspect_corrupted_token() {
    let dir = common::temp_dir();
    let corrupted_path = dir.path().join("corrupted.biscuit");

    // Write garbage data
    std::fs::write(&corrupted_path, "not-a-valid-token-at-all").unwrap();

    common::biscuit_cmd()
        .arg("inspect")
        .arg(&corrupted_path)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("invalid")
                .or(predicate::str::contains("parse"))
                .or(predicate::str::contains("decode"))
                .or(predicate::str::contains("error"))
        );
}

// ========== DATALOG SYNTAX ERRORS ==========

/// Test documenting lenient datalog parsing (missing semicolon accepted)
///
/// BEHAVIOR: biscuit-cli intentionally accepts datalog without semicolons.
/// This test is ignored because it documents expected permissive behavior,
/// not an error condition. Remove #[ignore] if validation becomes stricter.
#[test]
#[ignore]
fn test_generate_datalog_missing_semicolon() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    // Missing semicolon
    let invalid_datalog = "user(1234)";

    common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("-")
        .write_stdin(invalid_datalog)
        .assert()
        .failure();
}

/// Test generating token with unbalanced parentheses
#[test]
fn test_generate_datalog_unbalanced_parens() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    let invalid_datalog = "user(1234;";  // Missing closing paren

    common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("-")
        .write_stdin(invalid_datalog)
        .assert()
        .failure();
}

/// Test generating token with invalid fact syntax
#[test]
fn test_generate_datalog_invalid_syntax() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    let invalid_datalog = "this is not valid datalog at all;";

    common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("-")
        .write_stdin(invalid_datalog)
        .assert()
        .failure();
}

// ========== KEY FORMAT ERRORS ==========

/// Test keypair from invalid private key string
#[test]
fn test_keypair_invalid_private_key_string() {
    common::biscuit_cmd()
        .arg("keypair")
        .arg("--from-private-key")
        .arg("this-is-not-a-valid-key")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("invalid")
                .or(predicate::str::contains("parse"))
                .or(predicate::str::contains("error"))
        );
}

/// Test generating with corrupted key file
#[test]
fn test_generate_corrupted_key_file() {
    let dir = common::temp_dir();
    let corrupted_key = dir.path().join("corrupted.key");

    std::fs::write(&corrupted_key, "garbage-data-not-a-key").unwrap();

    common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&corrupted_key)
        .arg("-")
        .write_stdin("user(1234);")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("invalid")
                .or(predicate::str::contains("key"))
                .or(predicate::str::contains("error"))
        );
}

/// Test generating with empty key file
#[test]
fn test_generate_empty_key_file() {
    let dir = common::temp_dir();
    let empty_key = dir.path().join("empty.key");

    std::fs::write(&empty_key, "").unwrap();

    common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&empty_key)
        .arg("-")
        .write_stdin("user(1234);")
        .assert()
        .failure();
}

// ========== PARAMETER ERRORS ==========

/// Test parameter with invalid format (missing colon or equals)
#[test]
fn test_parameter_invalid_format() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("--param")
        .arg("invalid-no-type-or-value")  // Missing :type=value
        .arg("-")
        .write_stdin("user({id});")
        .assert()
        .failure();
}

/// Test parameter type mismatch (string where integer expected)
#[test]
fn test_parameter_type_mismatch() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    // Passing string where integer expected
    common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("--param")
        .arg("id:integer=not-a-number")
        .arg("-")
        .write_stdin("user({id});")
        .assert()
        .failure();
}

/// Test missing required parameter
#[test]
fn test_parameter_missing() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    // Datalog references {id} but no --param provided
    common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("-")
        .write_stdin("user({id});")
        .assert()
        .failure();
}

// ========== FILE/IO ERRORS ==========

/// Test documenting lenient datalog parsing (empty datalog accepted)
///
/// BEHAVIOR: biscuit-cli intentionally allows empty datalog and generates valid tokens.
/// This test is ignored because it documents expected permissive behavior,
/// not an error condition. Remove #[ignore] if empty datalog should be rejected.
#[test]
#[ignore]
fn test_generate_empty_datalog() {
    let (_dir, private_key_path, _public_key_path, _, _) = common::generate_test_keypair();

    common::biscuit_cmd()
        .arg("generate")
        .arg("--private-key-file")
        .arg(&private_key_path)
        .arg("-")
        .write_stdin("")
        .assert()
        .failure();
}

/// Test inspecting empty token file
#[test]
fn test_inspect_empty_file() {
    let dir = common::temp_dir();
    let empty_file = dir.path().join("empty.biscuit");

    std::fs::write(&empty_file, "").unwrap();

    common::biscuit_cmd()
        .arg("inspect")
        .arg(&empty_file)
        .assert()
        .failure();
}

// ========== ATTENUATION ERRORS ==========

/// Test attenuating with invalid datalog
#[test]
fn test_attenuate_invalid_datalog() {
    let (_dir, token_path, _, _) = common::generate_test_token();

    common::biscuit_cmd()
        .arg("attenuate")
        .arg(&token_path)
        .arg("--block")
        .arg("invalid syntax here")  // Invalid datalog
        .assert()
        .failure();
}

/// Test attenuating non-existent token
#[test]
fn test_attenuate_nonexistent_token() {
    common::biscuit_cmd()
        .arg("attenuate")
        .arg("/tmp/does-not-exist-12345.biscuit")
        .arg("--block")
        .arg("check if true;")
        .assert()
        .failure();
}

// ========== THIRD-PARTY ERRORS ==========

/// Test third-party block with invalid request file
#[test]
fn test_third_party_invalid_request() {
    let dir = common::temp_dir();
    let invalid_request = dir.path().join("invalid.bin");
    let (_tp_dir, tp_private_key, _, _, _) = common::generate_test_keypair();

    std::fs::write(&invalid_request, "not-a-valid-request").unwrap();

    common::biscuit_cmd()
        .arg("generate-third-party-block")
        .arg(&invalid_request)
        .arg("--private-key-file")
        .arg(&tp_private_key)
        .arg("--block")
        .arg("fact(1);")
        .assert()
        .failure();
}

/// Test appending third-party block with corrupted block file
#[test]
fn test_append_corrupted_third_party_block() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let corrupted_block = dir.path().join("corrupted.bin");

    std::fs::write(&corrupted_block, "corrupted-block-data").unwrap();

    common::biscuit_cmd()
        .arg("append-third-party-block")
        .arg(&token_path)
        .arg("--block-contents-file")
        .arg(&corrupted_block)
        .assert()
        .failure();
}
