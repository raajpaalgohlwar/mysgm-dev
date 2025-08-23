use super::provider::MySgmProvider;
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
use openmls_traits::{
    OpenMlsProvider,
    random::OpenMlsRand,
    types::{Ciphersuite, SignatureScheme},
};
use tls_codec::{Deserialize, Serialize};

#[derive(Debug)]
pub struct MySgmAgent {
    provider: MySgmProvider,
    capabilities: Capabilities,
    group_config: MlsGroupCreateConfig,
}

impl MySgmAgent {
    pub fn new(provider: MySgmProvider) -> Self {
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
            provider,
            capabilities,
            group_config,
        }
    }
    pub fn provider(&self) -> &MySgmProvider {
        &self.provider
    }
    pub fn key_package_counter(&self) -> u64 {
        self.provider.state().key_package_counter()
    }
    pub fn increment_key_package_counter(&mut self) -> Result<(), String> {
        self.provider.state_mut().increment_key_package_counter()
    }
    pub fn identities(&self) -> Vec<&str> {
        self.provider
            .state()
            .key_packages()
            .keys()
            .map(|k| k.as_ref())
            .collect()
    }
    pub fn groups(&self) -> Vec<&str> {
        self.provider
            .state()
            .group_ids()
            .iter()
            .map(|g| g.as_ref())
            .collect()
    }
    pub fn export_from_group(
        &self,
        gid_str: &str,
        label: &str,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
        let gid = GroupId::from_slice(gid_str.as_bytes());
        Ok(MlsGroup::load(self.provider.storage(), &gid)?
            .ok_or("Group not found")?
            .export_secret(&self.provider, label, &[], length)?)
    }
    pub fn create_group(&mut self, gid_str: &str) -> Result<(), Box<dyn core::error::Error>> {
        let gid = GroupId::from_slice(gid_str.as_bytes());
        let _ = MlsGroup::new_with_group_id(
            &self.provider,
            &self.provider,
            &self.group_config,
            gid.clone(),
            self.new_credential_with_key(),
        )?;
        self.provider.state_mut().add_group_id(gid_str.to_string());
        Ok(())
    }
    pub fn process_as_incoming_key_package(
        &mut self,
        bytes_in: &[u8],
    ) -> Result<(), Box<dyn core::error::Error>> {
        let kp = KeyPackageIn::tls_deserialize_exact(bytes_in)?
            .validate(self.provider.crypto(), self.provider.state().mls_version())?;
        self.provider.state_mut().add_key_package(
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
    pub fn new_key_package(&self) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
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
