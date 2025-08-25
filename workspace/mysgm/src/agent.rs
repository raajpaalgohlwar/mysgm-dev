use super::{
    keys::SignatureKeyPair, opendht::OpenDhtRestAdapter, provider::MySgmProvider, state::MySgmState,
};
use core::error::Error;
use hex::encode as hex_encode;
use openmls::{
    ciphersuite::signature::SignaturePublicKey,
    credentials::{BasicCredential, Credential, CredentialType, CredentialWithKey},
    extensions::ExtensionType,
    framing::{
        ApplicationMessage, ContentType, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
        ProcessedMessage, ProcessedMessageContent, ProtocolMessage, Sender as MlsSender,
    },
    group::{
        GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, QueuedProposal, StagedCommit,
        StagedWelcome,
    },
    key_packages::{KeyPackage, key_package_in::KeyPackageIn},
    messages::{Welcome, group_info::VerifiableGroupInfo, proposals::Proposal},
    prelude::Capabilities,
    schedule::PreSharedKeyId,
    treesync::LeafNodeParameters,
    versions::ProtocolVersion,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{
    OpenMlsProvider,
    random::OpenMlsRand,
    types::{Ciphersuite, SignatureScheme},
};
use serde_json::{from_str as json_decode, to_string as json_encode};
use std::fs::{read_to_string as read_file_to_string, write as write_string_to_file};
use tls_codec::{Deserialize, Serialize};

#[derive(Debug)]
pub struct MySgmAgent {
    adapter: OpenDhtRestAdapter,
    provider: MySgmProvider,
    capabilities: Capabilities,
    group_config: MlsGroupCreateConfig,
}

impl MySgmAgent {
    pub fn init(provider: MySgmProvider) -> Self {
        // opendht adapter
        let adapter = OpenDhtRestAdapter::new("localhost", 8000);
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
            .ciphersuite(provider.state().my_ciphersuite())
            .use_ratchet_tree_extension(true)
            .capabilities(capabilities.clone())
            .build();
        // done
        Self {
            adapter,
            provider,
            capabilities,
            group_config,
        }
    }
    pub fn new(pid: &str) -> Result<Self, Box<dyn Error>> {
        // crypto
        let crypto: RustCrypto = Default::default();
        // ciphersuite
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        // signature key pair
        let signature_key_pair = SignatureKeyPair::from_crypto(&crypto, ciphersuite.into())?;
        // new provider; done
        Ok(MySgmAgent::init(MySgmProvider::new(
            MySgmState::new(
                format!(
                    "{}__{}",
                    pid,
                    hex_encode(signature_key_pair.public_key_raw())
                        .chars()
                        .take(8)
                        .collect::<String>()
                ),
                signature_key_pair,
                ciphersuite,
                ProtocolVersion::Mls10,
            ),
            crypto,
        )))
    }
    pub fn load(file_path: &str) -> Result<Self, Box<dyn Error>> {
        Ok(MySgmAgent::init(MySgmProvider::new(
            json_decode(&read_file_to_string(file_path)?)?,
            Default::default(),
        )))
    }
    pub fn save(&self, file_path: &str) -> Result<(), Box<dyn Error>> {
        Ok(write_string_to_file(
            file_path,
            json_encode(self.provider.state())?,
        )?)
    }
    pub fn provider(&self) -> &MySgmProvider {
        &self.provider
    }
    pub fn agent_ids(&self) -> Vec<String> {
        self.provider.state().agent_ids()
    }
    pub fn group_ids(&self) -> Vec<String> {
        self.provider.state().group_ids()
    }
    pub fn export_from_group(
        &self,
        gid: &str,
        label: &str,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(MlsGroup::load(
            self.provider.storage(),
            &GroupId::from_slice(gid.as_bytes()),
        )?
        .ok_or("Group not found")?
        .export_secret(&self.provider, label, &[], length)?)
    }
    pub fn export_encoded_from_group(
        &self,
        gid: &str,
        label: &str,
        length: usize,
    ) -> Result<String, Box<dyn Error>> {
        Ok(hex_encode(self.export_from_group(gid, label, length)?))
    }
    pub fn create_group(&mut self, gid: &str) -> Result<(), Box<dyn Error>> {
        let gid_transformed = format!(
            "{}__{}",
            gid,
            hex::encode(self.provider().rand().random_vec(4).unwrap())
        );
        let _ = MlsGroup::new_with_group_id(
            &self.provider,
            &self.provider,
            &self.group_config,
            GroupId::from_slice(gid_transformed.as_bytes()),
            self.new_credential_with_key(),
        )?;
        self.provider.state_mut().add_group_id(gid_transformed);
        Ok(())
    }
    pub fn process_as_incoming_key_package(
        &mut self,
        bytes_in: &[u8],
    ) -> Result<(), Box<dyn core::error::Error>> {
        let kp = KeyPackageIn::tls_deserialize_exact(bytes_in)?
            .validate(self.provider.crypto(), self.provider.state().mls_version())?;
        self.provider.state_mut().set_key_package(
            &String::from_utf8_lossy(
                BasicCredential::try_from(kp.leaf_node().credential().clone())?.identity(),
            ),
            kp,
        );
        Ok(())
    }
    pub fn new_credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(
                self.provider.state().credential_str().as_bytes().to_vec(),
            )
            .into(),
            signature_key: self
                .provider
                .state()
                .signature_key_pair()
                .public_key_raw()
                .into(),
        }
    }
    pub fn new_key_package(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(KeyPackage::builder()
            .leaf_node_capabilities(self.capabilities.clone())
            .mark_as_last_resort()
            .build(
                self.provider.state().my_ciphersuite(),
                &self.provider,
                &self.provider,
                self.new_credential_with_key(),
            )?
            .key_package()
            .clone()
            .tls_serialize_detached()?)
    }
}
