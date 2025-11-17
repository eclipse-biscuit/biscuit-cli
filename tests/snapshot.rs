/*
 * SPDX-FileCopyrightText: 2025 David Legrand <me@davlgd.fr>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! Integration tests for snapshot functionality.
//!
//! These tests verify that:
//! - Snapshots can be created via `inspect --dump-snapshot-to`
//! - Snapshots can be inspected with `inspect-snapshot`
//! - Snapshot queries work correctly
//! - JSON output works for snapshots
//! - Stdin input works for snapshots
//!
//! IMPORTANT: Snapshots require an authorizer context to be created.
//! Use `--authorize-with` when creating snapshots.

mod common;

use predicates::prelude::*;

/// Test creating and inspecting a full snapshot
#[test]
fn test_create_and_inspect_snapshot() {
    let (dir, token_path, _, public_key) = common::generate_test_token();
    let snapshot_path = dir.path().join("snapshot.bin");
    let public_key_path = dir.path().join("public.key");
    std::fs::write(&public_key_path, &public_key).unwrap();

    // Create snapshot from token inspection with authorizer
    common::biscuit_cmd()
        .arg("inspect")
        .arg(&token_path)
        .arg("--public-key-file")
        .arg(&public_key_path)
        .arg("--authorize-with")
        .arg("allow if true;")
        .arg("--dump-snapshot-to")
        .arg(&snapshot_path)
        .assert()
        .success();

    // Verify snapshot file was created
    assert!(snapshot_path.exists(), "Snapshot file should be created");
    let snapshot_content = std::fs::read(&snapshot_path).unwrap();
    assert!(!snapshot_content.is_empty(), "Snapshot should not be empty");

    // Inspect the snapshot
    common::biscuit_cmd()
        .arg("inspect-snapshot")
        .arg(&snapshot_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(common::TEST_USER_ID));
}

/// Test creating and inspecting a policies snapshot
#[test]
fn test_create_and_inspect_policies_snapshot() {
    let (dir, token_path, _, public_key) = common::generate_test_token();
    let snapshot_path = dir.path().join("policies_snapshot.bin");
    let public_key_path = dir.path().join("public.key");
    std::fs::write(&public_key_path, &public_key).unwrap();

    // Create a policy to include in the snapshot
    let policy = "allow if user($id);";

    // Create policies snapshot
    common::biscuit_cmd()
        .arg("inspect")
        .arg(&token_path)
        .arg("--public-key-file")
        .arg(&public_key_path)
        .arg("--authorize-with")
        .arg(policy)
        .arg("--dump-policies-snapshot-to")
        .arg(&snapshot_path)
        .assert()
        .success();

    // Verify snapshot file was created
    assert!(snapshot_path.exists(), "Policies snapshot file should be created");

    // Inspect the policies snapshot
    // Note: Policies snapshots contain only rules, no facts, so authorization may fail
    // We just verify the snapshot can be read and contains the policy
    let output = common::biscuit_cmd()
        .arg("inspect-snapshot")
        .arg(&snapshot_path)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow if"), "Policies snapshot should contain policy");
}

/// Test inspecting snapshot with JSON output
#[test]
fn test_inspect_snapshot_json_output() {
    let (dir, token_path, _, public_key) = common::generate_test_token();
    let snapshot_path = dir.path().join("snapshot.bin");
    let public_key_path = dir.path().join("public.key");
    std::fs::write(&public_key_path, &public_key).unwrap();

    // Create snapshot with authorizer
    common::biscuit_cmd()
        .arg("inspect")
        .arg(&token_path)
        .arg("--public-key-file")
        .arg(&public_key_path)
        .arg("--authorize-with")
        .arg("allow if true;")
        .arg("--dump-snapshot-to")
        .arg(&snapshot_path)
        .assert()
        .success();

    // Inspect with JSON output
    let output = common::biscuit_cmd()
        .arg("inspect-snapshot")
        .arg(&snapshot_path)
        .arg("--json")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Verify it's valid JSON
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("Output should be valid JSON");
    assert!(json.is_object() || json.is_array(), "JSON output should be object or array");
}

/// Test snapshot with query
#[test]
fn test_snapshot_with_query() {
    let datalog = format!(
        "user({}); resource(\"{}\");",
        common::TEST_USER_ID,
        common::TEST_RESOURCE
    );
    let (dir, token_path, _, public_key) = common::generate_test_token_with_content(&datalog);
    let snapshot_path = dir.path().join("snapshot.bin");
    let public_key_path = dir.path().join("public.key");
    std::fs::write(&public_key_path, &public_key).unwrap();

    // Create snapshot with authorizer
    common::biscuit_cmd()
        .arg("inspect")
        .arg(&token_path)
        .arg("--public-key-file")
        .arg(&public_key_path)
        .arg("--authorize-with")
        .arg("allow if true;")
        .arg("--dump-snapshot-to")
        .arg(&snapshot_path)
        .assert()
        .success();

    // Query the snapshot with proper datalog rule syntax
    let output = common::biscuit_cmd()
        .arg("inspect-snapshot")
        .arg(&snapshot_path)
        .arg("--query")
        .arg("result($id) <- user($id)")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("result("), "Query should return result");
    assert!(stdout.contains(common::TEST_USER_ID), "Query should return user ID");
}

/// Test snapshot from stdin
#[test]
fn test_inspect_snapshot_from_stdin() {
    let (dir, token_path, _, public_key) = common::generate_test_token();
    let snapshot_path = dir.path().join("snapshot.bin");
    let public_key_path = dir.path().join("public.key");
    std::fs::write(&public_key_path, &public_key).unwrap();

    // Create snapshot with authorizer
    common::biscuit_cmd()
        .arg("inspect")
        .arg(&token_path)
        .arg("--public-key-file")
        .arg(&public_key_path)
        .arg("--authorize-with")
        .arg("allow if true;")
        .arg("--dump-snapshot-to")
        .arg(&snapshot_path)
        .assert()
        .success();

    // Read snapshot content
    let snapshot_content = std::fs::read(&snapshot_path).unwrap();

    // Inspect from stdin
    common::biscuit_cmd()
        .arg("inspect-snapshot")
        .arg("-")
        .write_stdin(&snapshot_content[..])
        .assert()
        .success()
        .stdout(predicate::str::contains(common::TEST_USER_ID));
}

/// Test inspect-snapshot with invalid/corrupted snapshot
#[test]
fn test_inspect_snapshot_invalid() {
    let dir = common::temp_dir();
    let corrupted_snapshot = dir.path().join("corrupted.bin");

    std::fs::write(&corrupted_snapshot, b"not-a-valid-snapshot").unwrap();

    common::biscuit_cmd()
        .arg("inspect-snapshot")
        .arg(&corrupted_snapshot)
        .assert()
        .failure();
}
