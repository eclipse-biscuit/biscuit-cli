/*
 * SPDX-FileCopyrightText: 2025 David Legrand <me@davlgd.fr>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! Integration tests for third-party blocks.
//!
//! Third-party blocks allow external parties to add blocks to a token without
//! having access to the original private key. This is useful for delegation scenarios.
//!
//! The workflow involves:
//! 1. Generate a third-party block request from the token
//! 2. Third party generates a block signed with their key
//! 3. Append the third-party block to the token
//!
//! These tests verify the complete third-party block workflow.

mod common;

/// Test complete third-party block workflow
#[test]
fn test_third_party_block_workflow() {
    // Step 1: Create a base token
    let (dir, token_path, _, _token_public_key) = common::generate_test_token();

    // Step 2: Generate a keypair for the third party
    let (_third_party_dir, third_party_private_path, _third_party_public_path, _, _third_party_public_key) =
        common::generate_test_keypair();

    // Step 3: Generate third-party block request
    let request_path = dir.path().join("request.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block-request")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&request_path, &output.get_output().stdout).unwrap();
    assert!(request_path.exists());

    // Step 4: Third party generates a block
    let third_party_block_path = dir.path().join("third_party_block.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block")
        .arg(&request_path)
        .arg("--private-key-file")
        .arg(&third_party_private_path)
        .arg("--block")
        .arg("third_party_fact(42);")
        .assert()
        .success();

    std::fs::write(&third_party_block_path, &output.get_output().stdout).unwrap();
    assert!(third_party_block_path.exists());

    // Step 5: Append third-party block to token
    let final_token_path = dir.path().join("token_with_third_party.biscuit");
    let output = common::biscuit_cmd()
        .arg("append-third-party-block")
        .arg(&token_path)
        .arg("--block-contents-file")
        .arg(&third_party_block_path)
        .assert()
        .success();

    std::fs::write(&final_token_path, &output.get_output().stdout).unwrap();
    assert!(final_token_path.exists());

    // Step 6: Inspect the final token
    let output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&final_token_path)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Should contain both original and third-party content
    assert!(stdout.contains("user(1234)")); // original authority
    assert!(stdout.contains("third_party_fact(42)")); // third-party block
}

/// Test generating third-party block request from stdin
#[test]
fn test_third_party_request_from_stdin() {
    let (_dir, token_path, _, _) = common::generate_test_token();

    // Read token content
    let token_content = std::fs::read_to_string(&token_path).unwrap();

    // Generate request from stdin
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block-request")
        .arg("-")
        .write_stdin(token_content.as_bytes())
        .assert()
        .success();

    // Should output request data
    let stdout = &output.get_output().stdout;
    assert!(!stdout.is_empty());
}

/// Test third-party block with complex datalog
#[test]
fn test_third_party_block_complex_datalog() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let (_third_party_dir, third_party_private_path, _, _, _third_party_public_key) = common::generate_test_keypair();

    // Generate request
    let request_path = dir.path().join("request.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block-request")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&request_path, &output.get_output().stdout).unwrap();

    // Generate third-party block with multiple facts and checks
    let datalog = "third_party_service(\"api\"); delegation_level(2); can_access(\"/api/users\"); check if delegation_level($level), $level < 5;";

    let third_party_block_path = dir.path().join("third_party_block.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block")
        .arg(&request_path)
        .arg("--private-key-file")
        .arg(&third_party_private_path)
        .arg("--block")
        .arg(datalog)
        .assert()
        .success();

    std::fs::write(&third_party_block_path, &output.get_output().stdout).unwrap();

    // Append to token
    let final_token_path = dir.path().join("token_with_third_party.biscuit");
    let output = common::biscuit_cmd()
        .arg("append-third-party-block")
        .arg(&token_path)
        .arg("--block-contents-file")
        .arg(&third_party_block_path)
        .assert()
        .success();

    std::fs::write(&final_token_path, &output.get_output().stdout).unwrap();

    // Verify all elements are present
    let output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&final_token_path)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("third_party_service"));
    assert!(stdout.contains("delegation_level"));
    assert!(stdout.contains("can_access"));
}

/// Test third-party block with parameters
#[test]
fn test_third_party_block_with_parameters() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let (_third_party_dir, third_party_private_path, _, _, _third_party_public_key) = common::generate_test_keypair();

    // Generate request
    let request_path = dir.path().join("request.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block-request")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&request_path, &output.get_output().stdout).unwrap();

    // Generate third-party block with parameters
    let third_party_block_path = dir.path().join("third_party_block.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block")
        .arg(&request_path)
        .arg("--private-key-file")
        .arg(&third_party_private_path)
        .arg("--block")
        .arg("delegation_count({count}); max_uses({max});")
        .arg("--param")
        .arg("count:integer=5")
        .arg("--param")
        .arg("max:integer=100")
        .assert()
        .success();

    std::fs::write(&third_party_block_path, &output.get_output().stdout).unwrap();

    // Append and verify
    let final_token_path = dir.path().join("token_with_third_party.biscuit");
    let output = common::biscuit_cmd()
        .arg("append-third-party-block")
        .arg(&token_path)
        .arg("--block-contents-file")
        .arg(&third_party_block_path)
        .assert()
        .success();

    std::fs::write(&final_token_path, &output.get_output().stdout).unwrap();

    let output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&final_token_path)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("delegation_count(5)"));
    assert!(stdout.contains("max_uses(100)"));
}

/// Test multiple third-party blocks
#[test]
fn test_multiple_third_party_blocks() {
    let (dir, token_path, _, _) = common::generate_test_token();

    // First third party
    let (_tp1_dir, tp1_private_path, _, _, _tp1_public_key) = common::generate_test_keypair();

    let request1_path = dir.path().join("request1.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block-request")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&request1_path, &output.get_output().stdout).unwrap();

    let tp1_block_path = dir.path().join("tp1_block.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block")
        .arg(&request1_path)
        .arg("--private-key-file")
        .arg(&tp1_private_path)
        .arg("--block")
        .arg("first_third_party(1);")
        .assert()
        .success();

    std::fs::write(&tp1_block_path, &output.get_output().stdout).unwrap();

    let token_with_tp1 = dir.path().join("token_tp1.biscuit");
    let output = common::biscuit_cmd()
        .arg("append-third-party-block")
        .arg(&token_path)
        .arg("--block-contents-file")
        .arg(&tp1_block_path)
        .assert()
        .success();

    std::fs::write(&token_with_tp1, &output.get_output().stdout).unwrap();

    // Second third party
    let (_tp2_dir, tp2_private_path, _, _, _tp2_public_key) = common::generate_test_keypair();

    let request2_path = dir.path().join("request2.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block-request")
        .arg(&token_with_tp1)
        .assert()
        .success();

    std::fs::write(&request2_path, &output.get_output().stdout).unwrap();

    let tp2_block_path = dir.path().join("tp2_block.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block")
        .arg(&request2_path)
        .arg("--private-key-file")
        .arg(&tp2_private_path)
        .arg("--block")
        .arg("second_third_party(2);")
        .assert()
        .success();

    std::fs::write(&tp2_block_path, &output.get_output().stdout).unwrap();

    let token_with_tp2 = dir.path().join("token_tp2.biscuit");
    let output = common::biscuit_cmd()
        .arg("append-third-party-block")
        .arg(&token_with_tp1)
        .arg("--block-contents-file")
        .arg(&tp2_block_path)
        .assert()
        .success();

    std::fs::write(&token_with_tp2, &output.get_output().stdout).unwrap();

    // Verify both third-party blocks are present
    let output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&token_with_tp2)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("user(1234)")); // original
    assert!(stdout.contains("first_third_party(1)"));
    assert!(stdout.contains("second_third_party(2)"));
}

/// Test that sealed token cannot have third-party blocks appended
#[test]
fn test_cannot_append_to_sealed_token() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let (_third_party_dir, third_party_private_path, _, _, _third_party_public_key) = common::generate_test_keypair();

    // Generate request before sealing
    let request_path = dir.path().join("request.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block-request")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&request_path, &output.get_output().stdout).unwrap();

    // Generate third-party block
    let third_party_block_path = dir.path().join("third_party_block.bin");
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block")
        .arg(&request_path)
        .arg("--private-key-file")
        .arg(&third_party_private_path)
        .arg("--block")
        .arg("third_party_fact(42);")
        .assert()
        .success();

    std::fs::write(&third_party_block_path, &output.get_output().stdout).unwrap();

    // Seal the token
    let sealed_path = dir.path().join("sealed.biscuit");
    let output = common::biscuit_cmd()
        .arg("seal")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&sealed_path, &output.get_output().stdout).unwrap();

    // Try to append third-party block to sealed token - should fail
    common::biscuit_cmd()
        .arg("append-third-party-block")
        .arg(&sealed_path)
        .arg("--block-contents-file")
        .arg(&third_party_block_path)
        .assert()
        .failure();
}

/// Test reading third-party block request from file (direct test for read_request_from)
#[test]
fn test_read_third_party_request_from_file() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let request_path = dir.path().join("request.bin");

    // Generate request to file
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block-request")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&request_path, &output.get_output().stdout).unwrap();

    // Verify request file exists and is not empty
    assert!(request_path.exists(), "Request file should be created");
    let request_content = std::fs::read(&request_path).unwrap();
    assert!(!request_content.is_empty(), "Request file should not be empty");

    // Use the request to generate a third-party block
    let (_tp_dir, tp_private_path, _, _, _) = common::generate_test_keypair();

    common::biscuit_cmd()
        .arg("generate-third-party-block")
        .arg(&request_path)
        .arg("--private-key-file")
        .arg(&tp_private_path)
        .arg("--block")
        .arg("test_fact(123);")
        .assert()
        .success();
}

/// Test appending third-party block with validation (direct test for append_third_party_from)
#[test]
fn test_append_third_party_block_validation() {
    let (dir, token_path, _, _) = common::generate_test_token();
    let request_path = dir.path().join("request.bin");

    // Generate request
    let output = common::biscuit_cmd()
        .arg("generate-third-party-block-request")
        .arg(&token_path)
        .assert()
        .success();

    std::fs::write(&request_path, &output.get_output().stdout).unwrap();

    // Generate third-party block
    let (_tp_dir, tp_private_path, _, _, _) = common::generate_test_keypair();
    let block_path = dir.path().join("block.bin");

    let output = common::biscuit_cmd()
        .arg("generate-third-party-block")
        .arg(&request_path)
        .arg("--private-key-file")
        .arg(&tp_private_path)
        .arg("--block")
        .arg("validated_fact(999);")
        .assert()
        .success();

    std::fs::write(&block_path, &output.get_output().stdout).unwrap();

    // Verify block file exists
    assert!(block_path.exists(), "Third-party block file should be created");
    let block_content = std::fs::read(&block_path).unwrap();
    assert!(!block_content.is_empty(), "Block file should not be empty");

    // Append the block and verify it works
    let final_token_path = dir.path().join("final.biscuit");
    let output = common::biscuit_cmd()
        .arg("append-third-party-block")
        .arg(&token_path)
        .arg("--block-contents-file")
        .arg(&block_path)
        .assert()
        .success();

    std::fs::write(&final_token_path, &output.get_output().stdout).unwrap();

    // Inspect to verify the appended block
    let output = common::biscuit_cmd()
        .arg("inspect")
        .arg(&final_token_path)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("validated_fact(999)"), "Third-party fact should be present");
}

