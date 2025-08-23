pub mod agent;
pub mod keys;
pub mod opendht;
pub mod provider;
pub mod state;

use agent::MySgmAgent;
use keys::SignatureKeyPair;
use provider::MySgmProvider;
use state::MySgmState;

use clap::Parser;
use hex::encode as hex_encode;
use openmls::versions::ProtocolVersion;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand, types::Ciphersuite};
use serde_json::{from_str as json_decode, to_string as json_encode};
use std::io::{BufRead, stdin};

/// Simple CLI for key generation
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Path to a JSON file to read (required)
    state_path: String,
    /// Command to execute (optional; without a command, the agent will just refresh itself)
    command: Option<String>,
    /// Optional identifier to use as credential
    #[arg(long, default_value = "agent")]
    pid: String,
    /// Optional identifier to use as group id
    #[arg(long, default_value = "group")]
    gid: String,
    /// Optional label for group export
    #[arg(long, default_value = "export")]
    export_label: String,
    /// Optional length for group export
    #[arg(long, default_value_t = 32)]
    export_length: usize,
}

fn main() {
    pretty_env_logger::init();
    // command-line args
    log::debug!("Parsing command-line arguments");
    let args = CliArgs::parse();
    log::debug!("Parsed command-line arguments");
    log::info!("Command-line arguments: {args:?}");
    // key-value database adapter
    let adapter = opendht::OpenDhtRestAdapter::new("localhost", 8000);
    // crypto
    let crypto: RustCrypto = Default::default();
    // state
    log::debug!("Initializing agent");
    log::debug!("Attempting to open state file for reading");
    log::info!("Path to state file: {}", args.state_path);
    let mut agent: MySgmAgent = match std::fs::read_to_string(&args.state_path) {
        Ok(state_json) => {
            log::debug!("Opened file; attempting to parse JSON");
            match json_decode(&state_json) {
                Ok(state) => {
                    log::debug!("Parsed JSON successfully");
                    MySgmAgent::new(MySgmProvider::new(state, crypto))
                }
                Err(e) => {
                    log::error!("Failed to parse JSON in file: {e}");
                    panic!("Terminated due to parse failure");
                }
            }
        }
        Err(e) => {
            log::error!("Failed to read file: {e}");
            log::warn!("Creating new state");
            let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
            let mls_version = ProtocolVersion::Mls10;
            let signature_key_pair =
                SignatureKeyPair::from_crypto(&crypto, ciphersuite.into()).unwrap();
            let new_agent = MySgmAgent::new(MySgmProvider::new(
                MySgmState::new(
                    format!(
                        "{}__{}",
                        args.pid.clone(),
                        hex_encode(signature_key_pair.public_key_raw())
                            .chars()
                            .take(8)
                            .collect::<String>()
                    ),
                    signature_key_pair,
                    ciphersuite,
                    mls_version,
                ),
                crypto,
            ));
            log::debug!("Attempting to write fresh state to disk");
            if let Err(e) = std::fs::write(
                &args.state_path,
                json_encode(new_agent.provider().state()).unwrap(),
            ) {
                log::error!("Failed to write state to disk: {e}");
                panic!("Terminated due to write failure");
            }
            log::debug!("Wrote state to disk");
            new_agent
        }
    };
    // collect key packages
    log::debug!("Attempting to collect new key packages");
    loop {
        let kp_counter = agent.key_package_counter();
        log::debug!("Fetching key package at position: {kp_counter}");
        match adapter.get(&format!("kp_{kp_counter}")) {
            Ok(None) => {
                log::debug!("No more key packages found");
                break;
            }
            Err(e) => {
                log::error!("Failed to get key package: {e}");
                break;
            }
            Ok(Some(kp_bytes)) => {
                log::info!("Received value: {}", hex::encode(&kp_bytes));
                log::debug!("Processing incoming key package");
                if let Err(e) = agent.process_as_incoming_key_package(&kp_bytes) {
                    log::error!("Failed to process incoming key package: {e}");
                }
                log::debug!("Finished processing incoming key package; continuing to fetch");
                agent.increment_key_package_counter().unwrap();
            }
        }
    }
    log::debug!("Finished collecting new key packages");
    // done with agent
    log::debug!("Initialized MySGM agent");
    log::info!("Agent: {agent:?}");
    // process command
    log::debug!("Processing command");
    match args.command {
        Some(cmd) => {
            log::info!("Command to process: {cmd}");
            match cmd.as_str() {
                "group_export" => {
                    let mut handle = stdin().lock();
                    log::debug!("Reading lines from stdin as groups for export");
                    for line in handle.lines() {
                        match line {
                            Ok(l) => {
                                log::info!("Group to use for export: {l}");
                                log::info!("Label to use for export: {}", args.export_label);
                                log::info!("Length to use for export: {}", args.export_length);
                                match agent.export_from_group(
                                    &l,
                                    &args.export_label,
                                    args.export_length,
                                ) {
                                    Ok(exported) => {
                                        println!("{}", hex::encode(&exported));
                                    }
                                    Err(e) => {
                                        log::error!("Failed to export secret: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Error reading line: {e}");
                                break;
                            }
                        }
                    }
                }
                "list_groups" => {
                    for gid in agent.groups() {
                        println!("{gid}");
                    }
                }
                "group_create" => {
                    let gid_str = format!(
                        "{}__{}",
                        args.gid,
                        hex::encode(agent.provider().rand().random_vec(4).unwrap())
                    );
                    match agent.create_group(&gid_str) {
                        Ok(()) => {
                            log::info!("Created group with ID: {gid_str}");
                        }
                        Err(e) => {
                            log::error!("Failed to create group: {e}");
                        }
                    }
                }
                "list_agents" => {
                    for kp_id in agent.identities() {
                        println!("{kp_id}");
                    }
                }
                "advertise" => {
                    let kp_counter = agent.key_package_counter();
                    loop {
                        log::debug!("Emplacing new key package at position: {kp_counter}");
                        match adapter.put_checked(
                            &format!("kp_{kp_counter}"),
                            &agent.new_key_package().unwrap(),
                        ) {
                            Ok(()) => {
                                break;
                            }
                            Err(e) => {
                                log::error!("Failed to put key package: {e}");
                                if e.to_string() == "Key already exists" {
                                    log::warn!("Continuing to fetch more key packages");
                                    agent.increment_key_package_counter().unwrap();
                                } else {
                                    panic!("Terminated due to failure to emplace key package");
                                }
                            }
                        }
                    }
                }
                _ => {
                    log::error!("Received unknown command");
                }
            }
        }
        None => {
            log::info!("No command to process");
        }
    }
    log::debug!("Finished processing command");
    // save state
    log::debug!("Attempting to write state back to disk");
    if let Err(e) = std::fs::write(
        &args.state_path,
        json_encode(agent.provider().state()).unwrap(),
    ) {
        log::error!("Failed to write state to disk: {e}");
        panic!("Terminated due to write failure");
    }
    log::debug!("Wrote state to disk");
    // done!
}
