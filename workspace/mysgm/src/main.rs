pub mod agent;
pub mod keys;
pub mod opendht;
pub mod provider;
pub mod state;

use agent::MySgmAgent;

use clap::Parser;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand};
use std::io::{BufRead, stdin};

/// Simple CLI for key generation
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Path to a JSON file to read (required)
    state_path: String,
    /// Optional flag to create new state
    #[arg(long)]
    new: bool,
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
    // load agent
    log::info!("Path to state file: {}", args.state_path);
    let mut agent = match args.new {
        true => {
            log::debug!("Creating new state");
            let new_agent = MySgmAgent::new(&args.pid).unwrap();
            log::debug!("Attempting to write fresh state to disk");
            new_agent.save(&args.state_path).unwrap();
            log::debug!("Wrote state to disk");
            new_agent
        }
        false => {
            log::debug!("Attempting to load state from file");
            MySgmAgent::load(&args.state_path).unwrap()
        }
    };
    // collect key packages
    /*
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
    */
    // done with agent
    log::debug!("Initialized MySGM agent");
    log::info!("Agent before processing command: {agent:?}");
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
                                match agent.export_encoded_from_group(
                                    &l,
                                    &args.export_label,
                                    args.export_length,
                                ) {
                                    Ok(exporter) => {
                                        println!("{exporter}");
                                    }
                                    Err(e) => {
                                        log::error!("Error exporting: {e}");
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
                    for gid in agent.group_ids() {
                        println!("{gid}");
                    }
                }
                "group_create" => {
                    agent.create_group(&args.gid).unwrap();
                }
                "list_agents" => {
                    for pid in agent.agent_ids() {
                        println!("{pid}");
                    }
                }
                "advertise" => {
                    /*
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
                        */
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
    log::info!("Agent after processing command: {agent:?}");
    // save state
    log::debug!("Attempting to write state back to disk");
    agent.save(&args.state_path).unwrap();
    log::debug!("Wrote state to disk");
    // done!
}
