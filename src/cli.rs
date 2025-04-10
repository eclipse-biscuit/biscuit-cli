/*
 * SPDX-FileCopyrightText: 2021 Clément Delafargue <clement@delafargue.name>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
use clap::Parser;
use std::path::PathBuf;

use crate::input::*;

/// biscuit manipulation program. It lets you create, attenuate, inspect biscuits, inspect snapshots and manage keypairs.
///
/// Common tasks:
/// - `biscuit keypair` to generate a new keypair
/// - `biscuit generate --private-key-file PRIVKEY_FILE` to create a biscuit token
/// - `biscuit attenuate FILE` to append a block to a biscuit token
/// - `biscuit inspect FILE` to inspect a biscuit token
/// - `biscuit inspect --public-key PUBKEY BISCUIT_FILE` to verify a biscuit signature
/// - `biscuit inspect-snapshot SNAPSHOT_FILE` to inspect a biscuit snapshot
#[derive(Parser)]
#[clap(version, author, verbatim_doc_comment)]
pub struct Opts {
    #[clap(subcommand)]
    pub subcmd: SubCommand,
}

#[derive(Parser)]
pub enum SubCommand {
    #[clap(name = "keypair")]
    KeyPairCmd(KeyPairCmd),
    Inspect(Box<Inspect>),
    InspectSnapshot(Box<InspectSnapshot>),
    Generate(Generate),
    Attenuate(Attenuate),
    GenerateThirdPartyBlockRequest(GenerateThirdPartyBlockRequest),
    GenerateThirdPartyBlock(GenerateThirdPartyBlock),
    AppendThirdPartyBlock(AppendThirdPartyBlock),
    Seal(Seal),
}

/// Create and manipulate key pairs
#[derive(Parser)]
#[clap(display_order(0))]
pub struct KeyPairCmd {
    /// Generate the keypair from the given private key. If omitted, a random keypair will be generated
    #[clap(long, value_name("PRIVATE_KEY"), conflicts_with("from-file"))]
    pub from_private_key: Option<String>,
    /// Generate the keypair from a private key stored in the given file (or use `-` to read it from stdin). If omitted, a random keypair will be generated
    #[clap(long, value_name("PRIVATE_KEY_FILE"))]
    pub from_file: Option<PathBuf>,
    /// Input format for the private key (when provided).
    #[clap(
        long,
        value_enum,
        default_value_t,
        value_name("PRIVATE_KEY_FORMAT"),
        requires("from-private-key"),
        requires("from-file")
    )]
    pub from_format: KeyFormat,
    /// Specify the private key algorithm, only when reading the private key raw bytes
    #[clap(
        long,
        value_enum,
        value_name("PRIVATE_KEY_ALGORITHM"),
        requires("from-file")
    )]
    pub from_algorithm: Option<Algorithm>,
    /// Key algorithm used when generating a keypair
    #[clap(
        long,
        value_enum,
        default_value_t,
        value_name("KEYPAIR_ALGORITHM"),
        conflicts_with("from-private-key"),
        conflicts_with("from-file")
    )]
    pub key_algorithm: Algorithm,

    /// Public and private key output format
    #[clap(long, value_enum, default_value_t)]
    pub key_output_format: KeyFormat,
    /// Only output the private key
    #[clap(long, conflicts_with("only-private-key"))]
    pub only_public_key: bool,
    /// Only output the public key
    #[clap(long, conflicts_with("only-public-key"))]
    pub only_private_key: bool,
}

/// Generate a biscuit from a private key and an authority block
#[derive(Parser)]
#[clap(display_order(1))]
pub struct Generate {
    /// Read the authority block from the given datalog file (or use `-` to read from stdin). If omitted, an interactive $EDITOR will be opened.
    #[clap(parse(from_os_str), value_name("DATALOG_FILE"))]
    pub authority_file: Option<PathBuf>,
    /// Provide a root key id, as a hint for public key selection
    #[clap(long)]
    pub root_key_id: Option<u32>,
    #[clap(flatten)]
    pub param_arg: common_args::ParamArg,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw: bool,
    #[clap(flatten)]
    pub private_key_args: common_args::PrivateKeyArgs,
    /// The optional context string attached to the authority block
    #[clap(long)]
    pub context: Option<String>,
    /// Add a TTL check to the generated block. You can either provide an expiration timestamp or a duration
    ///
    /// [examples: 2025-04-01T00:00:00Z, 1d, 15m]
    #[clap(
        long,
        parse(try_from_str = parse_ttl),
        value_name("TTL"),
        verbatim_doc_comment
    )]
    pub add_ttl: Option<Ttl>,
}

/// Attenuate an existing biscuit by adding a new block
#[derive(Parser)]
#[clap(display_order(2))]
pub struct Attenuate {
    #[clap(flatten)]
    pub biscuit_input_args: common_args::BiscuitInputArgs,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
    #[clap(flatten)]
    pub block_args: common_args::BlockArgs,
    #[clap(flatten)]
    pub param_arg: common_args::ParamArg,
}

/// Inspect a biscuit, optionally check its public key and run authorization.
#[derive(Parser)]
#[clap(display_order(3))]
pub struct Inspect {
    /// Output the results in a machine-readable format
    #[clap(long)]
    pub json: bool,
    #[clap(flatten)]
    pub biscuit_input_args: common_args::BiscuitInputArgs,
    /// Check the biscuit public key
    #[clap(long, conflicts_with("public-key-file"))]
    pub public_key: Option<String>,
    /// Check the biscuit public key
    #[clap(long, conflicts_with("public-key"), parse(from_os_str))]
    pub public_key_file: Option<PathBuf>,
    /// Input format for the public key. raw is only available when reading the public key from a file
    #[clap(long, value_enum, default_value_t)]
    pub public_key_format: KeyFormat,
    /// Specify the private key algorithm, only when reading the private key raw bytes
    #[clap(long, value_enum, requires("public-key-file"))]
    pub public_key_algorithm: Option<Algorithm>,
    #[clap(flatten)]
    pub run_limits_args: common_args::RunLimitArgs,
    #[clap(flatten)]
    pub authorization_args: common_args::AuthorizeArgs,
    #[clap(flatten)]
    pub query_args: common_args::QueryArgs,
    #[clap(flatten)]
    pub param_arg: common_args::ParamArg,
    /// Save the authorizer snapshot to a file
    ///
    /// This snapshot will contain the full authorization context, including the biscuit token and the evaluation results. This snapshot only contains the authorization context and does not carry any signatures. It cannot be used in place of a biscuit token.
    /// This is useful to audit the authorization process.
    #[clap(long, parse(from_os_str), value_name("SNAPSHOT_FILE"))]
    pub dump_snapshot_to: Option<PathBuf>,
    /// Output the snapshot raw bytes directly, with no base64 encoding
    #[clap(long, requires("dump-snapshot-to"))]
    pub dump_raw_snapshot: bool,
    /// Save a policies snapshot to a file
    ///
    /// This snapshot will only contain the authorizer rules, before the biscuit token is loaded, and before authorization is ran.
    /// This is useful when applying the same authorization rules every time.
    #[clap(long, parse(from_os_str), value_name("SNAPSHOT_FILE"))]
    pub dump_policies_snapshot_to: Option<PathBuf>,
    /// Output the policies snapshot raw bytes directly, with no base64 encoding
    #[clap(long, requires("dump-snapshot-to"))]
    pub dump_raw_policies_snapshot: bool,
}

/// Inspect a snapshot, optionally query it
#[derive(Parser)]
#[clap(display_order(4))]
pub struct InspectSnapshot {
    /// Output the results in a machine-readable format
    #[clap(long)]
    pub json: bool,
    /// Read the snapshot from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    pub snapshot_file: PathBuf,
    /// Read the snapshot raw bytes directly, with no base64 parsing
    #[clap(long)]
    pub raw_input: bool,
    #[clap(flatten)]
    pub run_limits_args: common_args::RunLimitArgs,
    #[clap(flatten)]
    pub query_args: common_args::QueryArgs,
    #[clap(flatten)]
    pub param_arg: common_args::ParamArg,
}

/// Generate a third-party block request from an existing biscuit
#[derive(Parser)]
#[clap(display_order(5))]
pub struct GenerateThirdPartyBlockRequest {
    #[clap(flatten)]
    pub biscuit_input_args: common_args::BiscuitInputArgs,
    /// Output the request raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
}

/// Generate a third-party block from a third-party block request
#[derive(Parser)]
#[clap(display_order(6))]
pub struct GenerateThirdPartyBlock {
    /// Read the request from the given file (or use `-` to read from stdin)
    #[clap(parse(from_os_str))]
    pub request_file: PathBuf,
    /// Read the request raw bytes directly, with no base64 parsing
    #[clap(long)]
    pub raw_input: bool,
    #[clap(flatten)]
    pub private_key_args: common_args::PrivateKeyArgs,
    /// Output the block raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
    #[clap(flatten)]
    pub block_args: common_args::BlockArgs,
    #[clap(flatten)]
    pub param_arg: common_args::ParamArg,
}

/// Append a third-party block to a biscuit
#[derive(Parser)]
#[clap(display_order(7))]
pub struct AppendThirdPartyBlock {
    #[clap(flatten)]
    pub biscuit_input_args: common_args::BiscuitInputArgs,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
    /// The third-party block to append to the token.
    #[clap(long)]
    pub block_contents: Option<String>,
    /// The third-party block to append to the token
    #[clap(
        long,
        parse(from_os_str),
        conflicts_with("block-contents"),
        required_unless_present("block-contents")
    )]
    pub block_contents_file: Option<PathBuf>,
    /// Read the third-party block contents raw bytes directly, with no base64 parsing
    #[clap(long, requires("block-contents-file"))]
    pub raw_block_contents: bool,
}

/// Seal a token, preventing further attenuation
#[derive(Parser)]
#[clap(display_order(8))]
pub struct Seal {
    #[clap(flatten)]
    pub biscuit_input_args: common_args::BiscuitInputArgs,
    /// Output the biscuit raw bytes directly, with no base64 encoding
    #[clap(long)]
    pub raw_output: bool,
}

mod common_args {
    use crate::input::*;
    use biscuit_auth::builder::Rule;
    use chrono::Duration;
    use clap::Parser;
    use std::path::PathBuf;

    /// Arguments related to queries
    #[derive(Parser)]
    pub struct QueryArgs {
        /// Query the authorizer after evaluation. If no authorizer is provided, query the token after evaluation.
        #[clap(
          long,
          value_parser = clap::builder::ValueParser::new(parse_rule),
          value_name("DATALOG_RULE")
        )]
        pub query: Option<Rule>,
        /// Query facts from all blocks (not just authority, authorizer or explicitly trusted blocks). Be careful, this can return untrustworthy facts.
        #[clap(long, requires("query"))]
        pub query_all: bool,
    }

    /// Arguments related to providing datalog parameters
    #[derive(Parser)]
    pub struct ParamArg {
        /// Provide a value for a datalog parameter.
        ///
        /// `type` is optional and defaults to `string`.
        /// Possible types are pubkey, string, integer, date, bytes or bool.
        /// Bytes values must be hex-encoded and start with `hex:`.
        /// Public keys must be hex-encoded and start with `ed25519/` or `secp256r1/`.
        /// Dates must be RFC3339 timestamps
        ///
        /// [examples: name=john, age:integer=42, is_happy:bool=true]
        #[clap(
        long,
        value_parser = clap::builder::ValueParser::new(parse_param),
        verbatim_doc_comment,
        value_name = "key[:type]=value",
    )]
        pub param: Vec<Param>,
    }

    /// Arguments related to runtime limits
    #[derive(Parser)]
    pub struct RunLimitArgs {
        /// Configure the maximum amount of facts that can be generated
        /// before aborting evaluation
        #[clap(long)]
        pub max_facts: Option<u64>,
        /// Configure the maximum amount of iterations before aborting
        /// evaluation
        #[clap(long)]
        pub max_iterations: Option<u64>,
        /// Configure the maximum evaluation duration before aborting.
        ///
        /// [examples: 100ms, 1s]
        #[clap(
            long,
            parse(try_from_str = parse_duration),
            value_name("DURATION"),
            verbatim_doc_comment
        )]
        pub max_time: Option<Duration>,
    }

    /// Arguments related to running authorization
    #[derive(Parser)]
    pub struct AuthorizeArgs {
        /// Open $EDITOR to provide an authorizer.
        #[clap(
            long,
            alias("verify-interactive"),
            conflicts_with("authorize-with"),
            conflicts_with("authorize-with-file"),
            conflicts_with("authorize-with-snapshot"),
            conflicts_with("authorize-with-snapshot-file")
        )]
        pub authorize_interactive: bool,
        /// Authorize the biscuit with the provided authorizer.
        #[clap(
            long,
            parse(from_os_str),
            alias("verify-with-file"),
            conflicts_with("authorize-with"),
            conflicts_with("authorize-with-snapshot"),
            conflicts_with("authorize-with-snapshot-file"),
            conflicts_with("authorize-interactive"),
            value_name("DATALOG_FILE")
        )]
        pub authorize_with_file: Option<PathBuf>,
        /// Authorize the biscuit with the provided authorizer
        #[clap(
            long,
            alias("verify-with"),
            conflicts_with("authorize-with-file"),
            conflicts_with("authorize-with-snapshot"),
            conflicts_with("authorize-with-snapshot-file"),
            conflicts_with("authorize-interactive"),
            value_name("DATALOG")
        )]
        pub authorize_with: Option<String>,
        /// Authorize the biscuit with the provided policies snapshot.
        #[clap(
            long,
            conflicts_with("authorize-with"),
            conflicts_with("authorize-with-file"),
            conflicts_with("authorize-with-snapshot-file"),
            conflicts_with("authorize-interactive"),
            value_name("SNAPSHOT")
        )]
        pub authorize_with_snapshot: Option<String>,
        /// Authorize the biscuit with the provided policies snapshot.
        #[clap(
            long,
            conflicts_with("authorize-with"),
            conflicts_with("authorize-with-file"),
            conflicts_with("authorize-with-snapshot"),
            conflicts_with("authorize-interactive"),
            value_name("SNAPSHOT_FILE")
        )]
        pub authorize_with_snapshot_file: Option<PathBuf>,
        /// Read the snapshot from a binary file
        #[clap(long, requires("authorize-with-snapshot-file"))]
        pub authorize_with_raw_snapshot_file: bool,
        /// Include the current time in the verifier facts
        #[clap(long)]
        pub include_time: bool,
    }

    /// Arguments related to defining a block
    #[derive(Parser)]
    pub struct BlockArgs {
        /// The block to append to the token. If `--block` and `--block-file` are omitted, an interactive $EDITOR will be opened.
        #[clap(long, value_name("DATALOG"))]
        pub block: Option<String>,
        /// The block to append to the token. If `--block` and `--block-file` are omitted, an interactive $EDITOR will be opened.
        #[clap(
            long,
            parse(from_os_str),
            conflicts_with = "block",
            value_name("DATALOG_FILE")
        )]
        pub block_file: Option<PathBuf>,
        /// The optional context string attached to the new block
        #[clap(long)]
        pub context: Option<String>,
        /// Add a TTL check to the generated block. You can either provide an expiration timestamp or a duration
        ///
        /// [examples: 2025-04-01T00:00:00Z, 1d, 15m]
        #[clap(
            long,
            parse(try_from_str = parse_ttl),
            value_name("TTL"),
            verbatim_doc_comment
        )]
        pub add_ttl: Option<Ttl>,
    }

    /// Arguments related to reading a biscuit
    #[derive(Parser)]
    pub struct BiscuitInputArgs {
        /// Read the biscuit from the given file (or use `-` to read from stdin)
        #[clap(parse(from_os_str))]
        pub biscuit_file: PathBuf,
        /// Read the biscuit raw bytes directly, with no base64 parsing
        #[clap(long)]
        pub raw_input: bool,
    }

    /// Arguments related to reading a private key for signing a block
    #[derive(Parser)]
    pub struct PrivateKeyArgs {
        /// The private key used to sign the block
        #[clap(long, required_unless_present("private-key-file"))]
        pub private_key: Option<String>,
        /// The private key used to sign the block
        #[clap(
            long,
            parse(from_os_str),
            required_unless_present("private-key"),
            conflicts_with = "private-key"
        )]
        pub private_key_file: Option<PathBuf>,
        /// Input format for the private key. raw is only available when reading the private key from a file or stdin
        #[clap(long, value_enum, default_value_t)]
        pub private_key_format: KeyFormat,
        /// Specify the private key algorithm, only when reading the private key raw bytes
        #[clap(
            long,
            value_enum,
            value_name("PRIVATE_KEY_ALGORITHM"),
            requires("private-key-file")
        )]
        pub private_key_algorithm: Option<Algorithm>,
    }
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Opts::command().debug_assert();
}
