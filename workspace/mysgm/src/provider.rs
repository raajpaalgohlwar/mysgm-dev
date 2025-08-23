use super::state::{MySgmState, OpenMlsKeyValueStore};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{
    OpenMlsProvider,
    crypto::OpenMlsCrypto,
    signatures::{Signer, SignerError},
    types::{CryptoError, SignatureScheme},
};

#[derive(Debug)]
pub struct MySgmProvider {
    state: MySgmState,
    crypto: RustCrypto,
}

impl MySgmProvider {
    pub fn new(state: MySgmState, crypto: RustCrypto) -> Self {
        Self { state, crypto }
    }
    pub fn state(&self) -> &MySgmState {
        &self.state
    }
    pub fn state_mut(&mut self) -> &mut MySgmState {
        &mut self.state
    }
}

impl OpenMlsProvider for MySgmProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = OpenMlsKeyValueStore;
    fn storage(&self) -> &Self::StorageProvider {
        self.state.openmls_values()
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl Signer for MySgmProvider {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.crypto
            .sign(
                self.state.signature_key_pair().signature_scheme(),
                payload,
                self.state.signature_key_pair().private_key_raw(),
            )
            .map_err(SignerError::CryptoError)
    }
    fn signature_scheme(&self) -> SignatureScheme {
        self.state.signature_key_pair().signature_scheme()
    }
}
