pub mod file_adapter;
pub mod keys;
pub mod opendht;
pub mod provider;
pub mod state;

use file_adapter::FileAdapter;
use keys::SignatureKeyPair;
use opendht::OpenDhtRestAdapter;
use provider::MySgmProvider;
use state::MySgmState;

use clap::{Parser, Subcommand, ValueEnum};
use core::error::Error;
use hex::encode as hex_encode;
use openmls::{
    credentials::{BasicCredential, Credential, CredentialType, CredentialWithKey},
    extensions::ExtensionType,
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessageContent},
    group::{
        GroupId, MergeCommitError, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
        MlsGroupStateError, ProcessMessageError, StagedWelcome,
    },
    key_packages::{KeyPackage, key_package_in::KeyPackageIn},
    prelude::{Capabilities, LeafNodeIndex},
    treesync::LeafNodeParameters,
    versions::ProtocolVersion,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{OpenMlsProvider, types::Ciphersuite};
use serde_json::{from_str as json_decode, to_string as json_encode};
use std::{
    fs::{read_to_string as read_file_to_string, write as write_string_to_file},
    io::{BufRead, stdin},
};
use tls_codec::{Deserialize, Serialize};

/// CLI for secure group messsaging agent
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Path to a JSON file to read (required)
    state_path: String,
    /// Option to reset state
    #[arg(long)]
    reset: bool,
    /// Optional identifier to use in generating pid
    #[arg(long, default_value = "agent")]
    pid: String,
    /// Command to execute
    #[command(subcommand)]
    main_command: MainCommands,
    /// Storage adapter to use for sharing state between agents
    #[arg(long, value_enum, default_value = "file")]
    adapter: AdapterKind,
    /// Directory to use with the file adapter
    #[arg(long, default_value = "/tmp")]
    file_path: String,
    /// DHT REST proxy host
    #[arg(long, default_value = "localhost")]
    dht_host: String,
    /// DHT REST proxy port
    #[arg(long, default_value_t = 8000)]
    dht_port: u16,
}

#[derive(Debug, Subcommand)]
enum MainCommands {
    Me {},
    Agents {},
    Groups {},
    Advertise {},
    CreateGroup {
        /// Optional gid for the new group
        #[arg(long, default_value = "group")]
        gid: String,
    },
    Group {
        /// gid for group commands
        gid: String,
        /// Command to execute
        #[command(subcommand)]
        group_command: GroupCommands,
    },
}

#[derive(Debug, Subcommand)]
enum GroupCommands {
    ExportSecret {
        /// Label for the exported secret
        #[arg(long)]
        label: String,
        /// Length for the exported secret
        #[arg(long)]
        length: usize,
    },
    Add {
        /// Agent IDs (pids) to add; if empty, read from stdin one per line.
        pids: Vec<String>,
    },
    Remove {
        /// Leaf indexes to remove; if empty, read from stdin one per line.
        indexes: Vec<u32>,
    },
    Members {},
    Update {},
}

#[derive(Clone, Debug, ValueEnum)]
enum AdapterKind {
    File,
    Dht,
}

trait StorageAdapter {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>>;
    fn put_checked(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn Error>>;
}

impl StorageAdapter for FileAdapter {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        FileAdapter::get(self, key)
    }

    fn put_checked(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn Error>> {
        FileAdapter::put_checked(self, key, value)
    }
}

impl StorageAdapter for OpenDhtRestAdapter {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        OpenDhtRestAdapter::get(self, key)
    }

    fn put_checked(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn Error>> {
        OpenDhtRestAdapter::put_checked(self, key, value)
    }
}


pub fn key_package_key(index: u64) -> String {
    format!("kp{index}")
}
pub fn welcome_message_key(index: u64) -> String {
    format!("wm{index}")
}

pub fn commit_key(group: &MlsGroup, provider: &MySgmProvider) -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "cm{}",
        hex_encode(group.export_secret(provider, "post_commit", &[], 32)?)
    ))
}

fn main() {
    pretty_env_logger::init();
    // CLI args
    let args = CliArgs::parse();
    log::info!("Command-line arguments: {args:?}");

    let adapter: Box<dyn StorageAdapter> = match args.adapter {
    AdapterKind::File => Box::new(FileAdapter::new(&args.file_path)),
    AdapterKind::Dht => Box::new(OpenDhtRestAdapter::new(&args.dht_host, args.dht_port)),
    };
    log::info!("Storage adapter: {}", match args.adapter {
        AdapterKind::File => "file",
        AdapterKind::Dht => "dht",
    });

    // crypto
    let crypto: RustCrypto = Default::default();
    // state
    log::info!("Path to agent state: {}", args.state_path);
    log::info!("Reset state? {}", args.reset);
    let state = if args.reset {
        log::warn!("Resetting state");
        // ciphersuite
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        // signature key pair
        let signature_key_pair =
            SignatureKeyPair::from_crypto(&crypto, ciphersuite.into()).unwrap();
        // new provider; done
        let pid_transformed = format!(
            "{}_{}",
            &args.pid,
            hex_encode(signature_key_pair.public_key_raw())
                .chars()
                .take(3)
                .collect::<String>()
        );
        MySgmState::new(
            pid_transformed,
            signature_key_pair,
            ciphersuite,
            ProtocolVersion::Mls10,
        )
    } else {
        log::debug!("Attempting to load state from file");
        json_decode(&read_file_to_string(&args.state_path).unwrap()).unwrap()
    };
    log::info!("State: {state:?}");
    // credential
    let cred_with_key = CredentialWithKey {
        credential: BasicCredential::new(state.my_pid().as_bytes().to_vec()).into(),
        signature_key: state.signature_key_pair().public_key_raw().into(),
    };
    // capabilities
    let capabilities = Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::LastResort]),
        None,
        Some(&[CredentialType::Basic]),
    );
    // config
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(state.my_ciphersuite())
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities.clone())
        .build();
    // provider
    let mut provider = MySgmProvider::new(state, crypto);
    // download key packages
    loop {
        let key = key_package_key(provider.state().key_package_counter());
        log::info!("Key package key to get: {key}");
        match adapter.get(&key) {
            Ok(Some(kp_bytes)) => {
                provider.state_mut().increment_key_package_counter();
                log::info!("Got key package bytes: {}", hex_encode(&kp_bytes));
                match MlsMessageIn::tls_deserialize_exact(kp_bytes)
                    .unwrap()
                    .extract()
                {
                    MlsMessageBodyIn::KeyPackage(kp_in) => {
                        let kp = kp_in
                            .validate(provider.crypto(), provider.state().mls_version())
                            .unwrap();
                        log::info!("Processed key package: {kp:?}");
                        let cred =
                            BasicCredential::try_from(kp.leaf_node().credential().clone()).unwrap();
                        let pid = String::from_utf8_lossy(cred.identity()).to_string();
                        log::info!("pid of key package: {pid}");
                        provider.state_mut().set_key_package(&pid, kp);
                    }
                    _ => {
                        panic!("Expected KeyPackage message");
                    }
                }
            }
            Ok(None) => {
                log::info!("No more key packages to download");
                break;
            }
            Err(e) => {
                panic!("Failed to get key package: {e}");
            }
        }
    }
    // download welcome messages
    loop {
        let key = welcome_message_key(provider.state().welcome_counter());
        log::info!("Welcome message key to get: {key}");
        match adapter.get(&key) {
            Ok(Some(wm_bytes)) => {
                provider.state_mut().increment_welcome_counter();
                log::info!("Got welcome message bytes: {}", hex_encode(&wm_bytes));
                match MlsMessageIn::tls_deserialize_exact(wm_bytes)
                    .unwrap()
                    .extract()
                {
                    MlsMessageBodyIn::Welcome(welcome) => {
                        log::info!("Processed welcome message: {welcome:?}");
                        match StagedWelcome::new_from_welcome(
                            &provider,
                            group_config.join_config(),
                            welcome,
                            None,
                        ) {
                            Ok(staged_welcome) => {
                                let group = staged_welcome.into_group(&provider).unwrap();
                                let gid = String::from_utf8_lossy(group.group_id().as_slice())
                                    .to_string();
                                log::info!("Group with gid: {gid}");
                                provider.state_mut().add_gid(gid.clone());
                            }
                            Err(e) => {
                                log::warn!("Failed to process welcome: {e}");
                            }
                        }
                    }
                    _ => {
                        panic!("Not a welcome message");
                    }
                }
            }
            Ok(None) => {
                log::info!("No more welcome messages to download");
                break;
            }
            Err(e) => {
                panic!("Failed to get welcome message: {e}");
            }
        }
    }
    // download commits
    for gid in provider.state().gids() {
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(gid.as_bytes()))
            .unwrap()
            .unwrap();
        loop {
            let key = match commit_key(&group, &provider) {
                Ok(k) => k,
                Err(e) if e.to_string().contains("evict") => {
                    log::warn!("Evicted from group, stopping commit download for gid: {gid}");
                    group.delete(provider.storage()).unwrap();
                    provider.state_mut().remove_gid(&gid);
                    break;
                }
                Err(e) => {
                    log::warn!("Failed to merge commit: {e}");
                    break;
                }
            };
            log::info!("Commit message key to get: {key}");
            match adapter.get(&key) {
                Ok(Some(cm_bytes)) => {
                    log::info!("Got commit message bytes: {}", hex_encode(&cm_bytes));
                    let proto_msg = MlsMessageIn::tls_deserialize_exact(cm_bytes)
                        .unwrap()
                        .try_into_protocol_message()
                        .unwrap();
                    match group.process_message(&provider, proto_msg) {
                        Ok(processed_message) => match processed_message.into_content() {
                            ProcessedMessageContent::StagedCommitMessage(commit_box) => {
                                match group.merge_staged_commit(&provider, *commit_box) {
                                    Ok(_) => {
                                        log::info!("Merged commit into group state for gid: {gid}");
                                    }
                                    Err(e) if e.to_string().contains("UseAfterEviction") => {
                                        log::warn!(
                                            "Evicted from group, stopping commit download for gid: {gid}"
                                        );
                                        provider.state_mut().remove_gid(&gid);
                                        break;
                                    }
                                    Err(e) => {
                                        log::warn!("Failed to merge commit: {e}");
                                        break;
                                    }
                                }
                            }
                            _ => panic!("Not a commit message"),
                        },
                        Err(e) => {
                            log::warn!("Failed to process commit message: {e}");
                            break;
                        }
                    }
                }
                Ok(None) => {
                    log::info!("No more commit messages to download for gid: {gid}");
                    break;
                }
                Err(e) => {
                    panic!("Failed to get commit message: {e}");
                }
            }
        }
    }
    // execute command
    log::info!("Command to process: {:?}", args.main_command);
    match &args.main_command {
        MainCommands::Me {} => {
            println!("{}", provider.state().my_pid());
        }
        MainCommands::Agents {} => {
            for pid in provider.state().pids() {
                println!("{pid}");
            }
        }
        MainCommands::Groups {} => {
            for gid in provider.state().gids() {
                println!("{gid}");
            }
        }
        MainCommands::CreateGroup { gid } => {
            let gid_transformed = format!(
                "{}_{}",
                gid,
                hex_encode(provider.state().signature_key_pair().public_key_raw())
                    .chars()
                    .take(3)
                    .collect::<String>()
            );
            match provider.state().gids().contains(&gid_transformed) {
                true => {
                    panic!("Group already exists");
                }
                false => {
                    let _ = MlsGroup::new_with_group_id(
                        &provider,
                        &provider,
                        &group_config,
                        GroupId::from_slice(gid_transformed.as_bytes()),
                        cred_with_key.clone(),
                    )
                    .unwrap();
                    provider.state_mut().add_gid(gid_transformed.clone());
                    println!("{gid_transformed}");
                }
            }
        }
        MainCommands::Advertise {} => {
            let key_package_bundle = KeyPackage::builder()
                .leaf_node_capabilities(capabilities.clone())
                .mark_as_last_resort()
                .build(
                    provider.state().my_ciphersuite(),
                    &provider,
                    &provider,
                    cred_with_key.clone(),
                )
                .unwrap();
            let key_package = key_package_bundle.key_package().clone();
            let my_pid = provider.state().my_pid().to_string();
            provider
                .state_mut()
                .set_key_package(&my_pid, key_package.clone());
            let kp_msg = MlsMessageOut::from(key_package)
                .tls_serialize_detached()
                .unwrap();
            log::info!("Key package to put: {}", hex_encode(&kp_msg));
            let mut index = provider.state().key_package_counter();
            loop {
                let key = key_package_key(index);
                log::info!("Key package key: {key}");
                match adapter.put_checked(&key, &kp_msg) {
                    Ok(()) => {
                        break;
                    }
                    Err(e) if e.to_string() == "Key already exists" => {
                        log::warn!("Failed to put key package: {e}");
                        index += 1;
                    }
                    Err(e) => {
                        panic!("{e}");
                    }
                }
            }
        }
        MainCommands::Group { gid, group_command } => {
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(gid.as_bytes()))
                    .unwrap()
                    .unwrap();
            match group_command {
                GroupCommands::ExportSecret { label, length } => {
                    println!(
                        "{}",
                        hex_encode(group.export_secret(&provider, label, &[], *length).unwrap())
                    );
                }
                GroupCommands::Members {} => {
                    let mut pids: Vec<String> = Vec::new();
                    for member in group.members() {
                        let cred = BasicCredential::try_from(member.credential.clone()).unwrap();
                        println!(
                            "{} {}",
                            member.index,
                            String::from_utf8_lossy(cred.identity())
                        );
                    }
                }
                GroupCommands::Remove { indexes } => {
                    let mut indexes: Vec<LeafNodeIndex> = indexes
                        .iter()
                        .map(|index| LeafNodeIndex::new(*index))
                        .collect();
                    if indexes.is_empty() {
                        let handle = stdin().lock();
                        log::debug!("Reading lines from stdin as indexes to remove");
                        for line in handle.lines() {
                            match line {
                                Ok(l) => {
                                    log::info!("index: {l}");
                                    indexes.push(LeafNodeIndex::new(l.parse::<u32>().unwrap()));
                                }
                                Err(e) => {
                                    log::error!("Error reading line: {e}");
                                    break;
                                }
                            }
                        }
                    }
                    let (commit, welcome_opt, _) = group
                        .remove_members(&provider, &provider, indexes.as_slice())
                        .unwrap();
                    log::info!("Commit message: {:?}", commit);
                    let key = commit_key(&group, &provider).unwrap();
                    adapter
                        .put_checked(&key, &commit.tls_serialize_detached().unwrap())
                        .unwrap();
                    group.merge_pending_commit(&provider).unwrap();
                    if let Some(welcome) = welcome_opt {
                        log::info!("Welcome message: {:?}", welcome);
                        let mut index = provider.state().welcome_counter();
                        loop {
                            let key = welcome_message_key(index);
                            log::info!("Welcome message key: {key}");
                            match adapter
                                .put_checked(&key, &welcome.tls_serialize_detached().unwrap())
                            {
                                Ok(()) => {
                                    break;
                                }
                                Err(e) if e.to_string() == "Key already exists" => {
                                    log::warn!("Failed to put key package: {e}");
                                    index += 1;
                                }
                                Err(e) => {
                                    panic!("{e}");
                                }
                            }
                        }
                    }
                }
                GroupCommands::Add { pids } => {
                    let mut input_pids = pids.clone();
                    let mut kps = Vec::new();
                    if input_pids.is_empty() {
                        let handle = stdin().lock();
                        log::debug!("Reading lines from stdin as agents to add");
                        for line in handle.lines() {
                            match line {
                                Ok(l) => {
                                    input_pids.push(l);
                                }
                                Err(e) => {
                                    log::error!("Error reading line: {e}");
                                    break;
                                }
                            }
                        }
                    }
                    for pid in input_pids {
                        log::info!("pid: {pid}");
                        match provider.state().key_package(&pid) {
                            Some(kp) => {
                                log::info!("Key package for pid: {kp:?}");
                                kps.push(kp.clone());
                            }
                            None => {
                                panic!("No key package for pid: {pid}");
                            }
                        }
                    }
                    let (commit, welcome, _) = group
                        .add_members_without_update(&provider, &provider, kps.as_slice())
                        .unwrap();
                    log::info!("Commit message: {:?}", commit);
                    let key = commit_key(&group, &provider).unwrap();
                    adapter
                        .put_checked(&key, &commit.tls_serialize_detached().unwrap())
                        .unwrap();
                    group.merge_pending_commit(&provider).unwrap();
                    log::info!("Welcome message: {:?}", welcome);
                    let mut index = provider.state().welcome_counter();
                    loop {
                        let key = welcome_message_key(index);
                        log::info!("Welcome message key: {key}");
                        match adapter.put_checked(&key, &welcome.tls_serialize_detached().unwrap())
                        {
                            Ok(()) => {
                                break;
                            }
                            Err(e) if e.to_string() == "Key already exists" => {
                                log::warn!("Failed to put key package: {e}");
                                index += 1;
                            }
                            Err(e) => {
                                panic!("{e}");
                            }
                        }
                    }
                }
                GroupCommands::Update {} => {
                    let (commit, welcome_opt, _) = group
                        .self_update(
                            &provider,
                            &provider,
                            LeafNodeParameters::builder()
                                .with_capabilities(capabilities.clone())
                                .build(),
                        )
                        .unwrap()
                        .into_messages();
                    log::info!("Commit message: {:?}", commit);
                    let key = commit_key(&group, &provider).unwrap();
                    adapter
                        .put_checked(&key, &commit.tls_serialize_detached().unwrap())
                        .unwrap();
                    group.merge_pending_commit(&provider).unwrap();
                    if let Some(welcome) = welcome_opt {
                        log::info!("Welcome message: {:?}", welcome);
                        let mut index = provider.state().welcome_counter();
                        loop {
                            let key = welcome_message_key(index);
                            log::info!("Welcome message key: {key}");
                            match adapter
                                .put_checked(&key, &welcome.tls_serialize_detached().unwrap())
                            {
                                Ok(()) => {
                                    break;
                                }
                                Err(e) if e.to_string() == "Key already exists" => {
                                    log::warn!("Failed to put key package: {e}");
                                    index += 1;
                                }
                                Err(e) => {
                                    panic!("{e}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // save state
    log::info!("State before saving: {:?}", provider.state());
    write_string_to_file(&args.state_path, json_encode(provider.state()).unwrap()).unwrap();
    // done
}