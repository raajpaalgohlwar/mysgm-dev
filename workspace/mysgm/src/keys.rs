//! Custom data structures for signing keys for OpenMLS.
//!
//! This module provides custom data structures for handling signing keys
//! used in OpenMLS (Message Layer Security) credentials. It includes structures
//! for public signature keys and signature key pairs, along with their
//! associated methods and traits.

use hex::encode as hex_encode;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    storage::{CURRENT_VERSION, Entity, Key, traits},
    types::{CryptoError, SignatureScheme},
};
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

/// A public signature key to be used instead of the default provided data structure.
///
/// This structure represents a public signature key, which is used in cryptographic
/// operations within MLS credentials. It provides methods to access the key's value
/// and implements necessary traits for storage and conversion.
#[derive(
    Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub struct SignaturePublicKey {
    value: Vec<u8>,
}

impl core::fmt::Debug for SignaturePublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignaturePublicKey")
            .field("value", &format!("0x{}", hex_encode(&self.value)))
            .finish()
    }
}

impl Key<CURRENT_VERSION> for SignaturePublicKey {}

impl traits::SignaturePublicKey<CURRENT_VERSION> for SignaturePublicKey {}

impl From<SignaturePublicKey> for Vec<u8> {
    /// Converts a `SignaturePublicKey` into a `Vec<u8>`.
    ///
    /// This method allows for easy conversion of the public key into a byte vector,
    /// which can be useful for serialization or other operations requiring raw bytes.
    fn from(key: SignaturePublicKey) -> Vec<u8> {
        key.value
    }
}

impl SignaturePublicKey {
    /// Returns a reference to the bytes of the signature public key.
    ///
    /// This method provides access to the raw byte representation of the public key.
    ///
    /// # Returns
    ///
    /// A slice of bytes representing the public key.
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }
}

/// A signature key pair to be used instead of the default provided data structure.
///
/// This structure represents a pair of private and public keys used for signing
/// operations within MLS credentials. It includes methods to access the keys and
/// the signature scheme used to generate them.
#[derive(
    Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub struct SignatureKeyPair {
    private: Vec<u8>,
    public: Vec<u8>,
    signature_scheme: SignatureScheme,
}

impl core::fmt::Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("private", &format!("0x{}", hex_encode(&self.private)))
            .field("public", &format!("0x{}", hex_encode(&self.public)))
            .field("signature_scheme", &self.signature_scheme)
            .finish()
    }
}

impl Entity<CURRENT_VERSION> for SignatureKeyPair {}

impl traits::SignatureKeyPair<CURRENT_VERSION> for SignatureKeyPair {}

impl SignatureKeyPair {
    /// Creates a new `SignatureKeyPair` from raw private and public keys and a signature scheme.
    ///
    /// # Parameters
    ///
    /// - `private`: The raw private key bytes.
    /// - `public`: The raw public key bytes.
    /// - `signature_scheme`: The signature scheme used to generate the keys.
    ///
    /// # Returns
    ///
    /// A new `SignatureKeyPair` instance.
    pub fn from_raw(private: Vec<u8>, public: Vec<u8>, signature_scheme: SignatureScheme) -> Self {
        Self {
            private,
            public,
            signature_scheme,
        }
    }
    /// Generates a new `SignatureKeyPair` using the provided cryptographic provider and signature scheme.
    ///
    /// # Parameters
    ///
    /// - `crypto`: The cryptographic provider implementing `OpenMlsCrypto`.
    /// - `signature_scheme`: The signature scheme to be used for key generation.
    ///
    /// # Returns
    ///
    /// A result containing the new `SignatureKeyPair` instance or a `CryptoError`.
    pub fn from_crypto<T: OpenMlsCrypto>(
        crypto: &T,
        signature_scheme: SignatureScheme,
    ) -> Result<Self, CryptoError> {
        let (private, public) = crypto.signature_key_gen(signature_scheme)?;
        Ok(Self {
            private,
            public,
            signature_scheme,
        })
    }
}

impl SignatureKeyPair {
    /// Returns a reference to the bytes of the signature private key.
    ///
    /// This method provides access to the raw byte representation of the private key.
    ///
    /// # Returns
    ///
    /// A slice of bytes representing the private key.
    pub fn private_key_raw(&self) -> &[u8] {
        self.private.as_slice()
    }
    /// Returns a reference to the bytes of the signature public key.
    ///
    /// This method provides access to the raw byte representation of the public key.
    ///
    /// # Returns
    ///
    /// A slice of bytes representing the public key.
    pub fn public_key_raw(&self) -> &[u8] {
        self.public.as_slice()
    }
    /// Returns the `SignatureScheme` used to generate this key pair.
    ///
    /// This method provides access to the signature scheme associated with this key pair,
    /// which defines the cryptographic algorithm used for signing operations.
    ///
    /// # Returns
    ///
    /// The `SignatureScheme` used to generate this key pair.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
    /// Returns a copy of the signature public key structure.
    ///
    /// This method creates a new `SignaturePublicKey` instance containing the same
    /// public key value as this key pair.
    ///
    /// # Returns
    ///
    /// A `SignaturePublicKey` instance with the same public key value.
    pub fn public_key(&self) -> SignaturePublicKey {
        SignaturePublicKey {
            value: self.public.clone(),
        }
    }
}
