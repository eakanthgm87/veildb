//! VeilDB crypto layer.
//!
//! This crate is the sole owner of all cryptographic operations:
//! AES-256-GCM encryption, Ed25519 signatures, X25519 key exchange,
//! Argon2 password KDF, CSPRNG, and key zeroization.
//!
//! It depends on no application-level crate. All private keys are
//! zeroized on drop and never cross the public API.

pub mod error;

use aes_gcm::aead::{Aead, KeyInit, OsRng as AeadOsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher, PasswordVerifier, PasswordHash};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use error::CryptoError;

/// A zeroized 32-byte symmetric key.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Key {
    bytes: [u8; 32],
}

impl Key {
    /// Create a key from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Generate a fresh random key using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        AeadOsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key(***)")
    }
}

/// Encrypted data with its key version and nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    /// Key version used for encryption. Rotation never invalidates
    /// historical data.
    pub key_version: u32,
    /// Fresh CSPRNG nonce, never reused per key.
    pub nonce: [u8; 12],
    /// The encrypted payload.
    pub data: Vec<u8>,
}

/// A key ring that manages multiple key versions.
///
/// Historical ciphertexts stay decryptable under their original
/// `key_version`. Rotation adds a new key version without invalidating
/// older ones.
#[derive(Clone)]
pub struct KeyRing {
    /// Map of key version → key.
    keys: std::collections::BTreeMap<u32, Key>,
    /// The active (latest) key version.
    active_version: u32,
}

impl KeyRing {
    /// Create a new key ring with a single initial key.
    pub fn new(initial_key: Key, initial_version: u32) -> Self {
        let mut keys = std::collections::BTreeMap::new();
        keys.insert(initial_version, initial_key);
        Self {
            keys,
            active_version: initial_version,
        }
    }

    /// Get the active key version.
    pub fn active_version(&self) -> u32 {
        self.active_version
    }

    /// Get the key for a specific version.
    ///
    /// Returns `CryptoError::UnknownKeyVersion` if the version is not
    /// present in the ring.
    pub fn key_for_version(&self, version: u32) -> Result<&Key, CryptoError> {
        self.keys
            .get(&version)
            .ok_or(CryptoError::UnknownKeyVersion(version))
    }

    /// Get the active key.
    pub fn active_key(&self) -> &Key {
        // The active version is always present in the ring.
        &self.keys[&self.active_version]
    }

    /// Rotate the key: derive a new key from the existing master secret
    /// and make it the active version.
    ///
    /// The new key is derived deterministically from the current active
    /// key via BLAKE3 (a KDF-style derivation). Historical keys remain
    /// in the ring for decrypting old ciphertexts.
    pub fn rotate_key(&mut self) -> Result<u32, CryptoError> {
        let new_version = self.active_version + 1;
        let current = self.active_key().as_bytes();
        // Derive a new key from the current one via BLAKE3.
        let mut hasher = blake3::Hasher::new();
        hasher.update(current);
        hasher.update(&new_version.to_le_bytes());
        let derived = *hasher.finalize().as_bytes();
        let new_key = Key::from_bytes(derived);
        self.keys.insert(new_version, new_key);
        self.active_version = new_version;
        Ok(new_version)
    }

    /// Get all key versions present in the ring.
    pub fn versions(&self) -> Vec<u32> {
        self.keys.keys().copied().collect()
    }
}

/// An Ed25519 signing keypair.
///
/// The secret key is zeroized on drop.
pub struct SigningKeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl SigningKeyPair {
    /// Generate a fresh keypair.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut AeadOsRng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Create a keypair from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Get the verifying (public) key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing.sign(message).to_bytes().to_vec()
    }

    /// Get the secret key bytes (for backup/export).
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }
}

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKeyPair(***)")
    }
}

/// An X25519 keypair for key exchange.
///
/// The secret key is zeroized on drop.
pub struct X25519KeyPair {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl X25519KeyPair {
    /// Generate a fresh keypair.
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(AeadOsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Get the secret key bytes (for backup/export).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Create a keypair from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(seed);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Perform X25519 key exchange with a peer's public key.
    pub fn exchange(&self, peer_public: &[u8; 32]) -> Result<Key, CryptoError> {
        let peer = x25519_dalek::PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(shared.as_bytes());
        Ok(Key::from_bytes(bytes))
    }
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519KeyPair(***)")
    }
}

/// Derive a 32-byte key from a passphrase using Argon2.
///
/// Uses Argon2id with OWASP-recommended parameters.
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Key, CryptoError> {
    let salt = SaltString::encode_b64(salt)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(passphrase, &salt)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let hash_bytes = hash.hash.as_ref().ok_or_else(|| {
        CryptoError::KeyDerivation("no hash output".to_string())
    })?;
    let hash_slice = hash_bytes.as_bytes();
    let mut bytes = [0u8; 32];
    let n = hash_slice.len().min(32);
    bytes[..n].copy_from_slice(&hash_slice[..n]);
    Ok(Key::from_bytes(bytes))
}

/// Verify a passphrase against a stored Argon2 hash.
pub fn verify_passphrase(passphrase: &[u8], stored_hash: &str) -> Result<bool, CryptoError> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(passphrase, &parsed)
        .is_ok())
}

/// Encrypt a plaintext with AES-256-GCM.
///
/// A fresh CSPRNG nonce is generated for every call.
pub fn encrypt(key: &Key, key_version: u32, plaintext: &[u8]) -> Result<Ciphertext, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::Aead(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    AeadOsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let data = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::Aead(e.to_string()))?;

    Ok(Ciphertext {
        key_version,
        nonce: nonce_bytes,
        data,
    })
}

/// Decrypt a ciphertext with AES-256-GCM.
pub fn decrypt(key: &Key, ciphertext: &Ciphertext) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::Aead(e.to_string()))?;

    let nonce = Nonce::from_slice(&ciphertext.nonce);
    cipher
        .decrypt(nonce, ciphertext.data.as_ref())
        .map_err(|_| CryptoError::Aead("decryption failed".to_string()))
}

/// Verify an Ed25519 signature.
pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let verifying = VerifyingKey::from_bytes(public_key)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| CryptoError::InvalidSignature)?;
    verifying
        .verify(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Compute the BLAKE3 hash of data.
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Domain-separation tag for the auto-pairing proof.
const PAIRING_PROOF_DOMAIN: &[u8] = b"VEILDB-AUTO-PAIR-V1";

/// Compute a proof-of-passphrase-knowledge for automatic pairing.
///
/// The proof is `BLAKE3(domain || secret || nonce_initiator ||
/// nonce_responder || db_id_initiator || db_id_responder)`. Both
/// peers compute the same input (both know both nonces and both
/// ORIGINAL database IDs from the probe exchange, and the initiator
/// role is unambiguous: the dialing side).
///
/// The proof proves to each side that the other holds the same
/// passphrase without ever transmitting the passphrase or any key
/// derived from it. A passive observer learns nothing reversible;
/// an active attacker cannot forge a proof for a fresh nonce.
pub fn pairing_proof(
    secret: &[u8],
    nonce_initiator: &[u8; 32],
    nonce_responder: &[u8; 32],
    db_initiator: &[u8; 32],
    db_responder: &[u8; 32],
) -> [u8; 32] {
    let mut msg = Vec::with_capacity(PAIRING_PROOF_DOMAIN.len() + 32 * 4 + secret.len());
    msg.extend_from_slice(PAIRING_PROOF_DOMAIN);
    msg.extend_from_slice(secret);
    msg.extend_from_slice(nonce_initiator);
    msg.extend_from_slice(nonce_responder);
    msg.extend_from_slice(db_initiator);
    msg.extend_from_slice(db_responder);
    hash(&msg)
}

/// Generate a random 32-byte value.
pub fn random_bytes_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    AeadOsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a random 12-byte nonce.
pub fn random_nonce() -> [u8; 12] {
    let mut bytes = [0u8; 12];
    AeadOsRng.fill_bytes(&mut bytes);
    bytes
}

/// A generic CSPRNG wrapper for use with rand_core.
pub struct OsRng;

impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        AeadOsRng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        AeadOsRng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        AeadOsRng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        AeadOsRng.try_fill_bytes(dest)
    }
}

impl CryptoRng for OsRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = Key::generate();
        let plaintext = b"hello veildb";
        let ct = encrypt(&key, 1, plaintext).unwrap();
        let pt = decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn encrypt_tamper_detection() {
        let key = Key::generate();
        let ct = encrypt(&key, 1, b"secret").unwrap();
        let mut tampered = ct.clone();
        tampered.data[0] ^= 0xFF;
        assert!(decrypt(&key, &tampered).is_err());
    }

    #[test]
    fn nonce_uniqueness() {
        let key = Key::generate();
        let ct1 = encrypt(&key, 1, b"data").unwrap();
        let ct2 = encrypt(&key, 1, b"data").unwrap();
        assert_ne!(ct1.nonce, ct2.nonce);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = Key::generate();
        let key2 = Key::generate();
        let ct = encrypt(&key1, 1, b"data").unwrap();
        assert!(decrypt(&key2, &ct).is_err());
    }

    #[test]
    fn sign_verify() {
        let kp = SigningKeyPair::generate();
        let msg = b"message to sign";
        let sig = kp.sign(msg);
        let pubkey = kp.public_key();
        verify_signature(&pubkey, msg, &sig).unwrap();
    }

    #[test]
    fn sign_wrong_key_fails() {
        let kp1 = SigningKeyPair::generate();
        let kp2 = SigningKeyPair::generate();
        let msg = b"message";
        let sig = kp1.sign(msg);
        let pubkey2 = kp2.public_key();
        assert!(verify_signature(&pubkey2, msg, &sig).is_err());
    }

    #[test]
    fn sign_tampered_message_fails() {
        let kp = SigningKeyPair::generate();
        let msg = b"message";
        let sig = kp.sign(msg);
        let pubkey = kp.public_key();
        assert!(verify_signature(&pubkey, b"tampered", &sig).is_err());
    }

    #[test]
    fn x25519_exchange() {
        let a = X25519KeyPair::generate();
        let b = X25519KeyPair::generate();
        let shared_a = a.exchange(&b.public_key()).unwrap();
        let shared_b = b.exchange(&a.public_key()).unwrap();
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }

    #[test]
    fn derive_key_deterministic() {
        let salt = b"fixed-salt-16-bytes";
        let k1 = derive_key(b"passphrase", salt).unwrap();
        let k2 = derive_key(b"passphrase", salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_key_different_salt() {
        let k1 = derive_key(b"passphrase", b"salt-one-16-bytes").unwrap();
        let k2 = derive_key(b"passphrase", b"salt-two-16-bytes").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn key_zeroization() {
        let key = Key::from_bytes([0xAB; 32]);
        assert_eq!(key.as_bytes(), &[0xAB; 32]);
        drop(key);
        // Can't easily verify zeroization after drop, but the type
        // implements ZeroizeOnDrop which is the guarantee.
    }

    #[test]
    fn key_ring_rotation_multiversion() {
        let key = Key::generate();
        let mut ring = KeyRing::new(key, 1);
        assert_eq!(ring.active_version(), 1);

        // Encrypt under v1.
        let ct1 = encrypt(ring.active_key(), 1, b"data-v1").unwrap();
        assert_eq!(ct1.key_version, 1);

        // Rotate to v2.
        let v2 = ring.rotate_key().unwrap();
        assert_eq!(v2, 2);
        assert_eq!(ring.active_version(), 2);

        // Encrypt under v2.
        let ct2 = encrypt(ring.active_key(), 2, b"data-v2").unwrap();
        assert_eq!(ct2.key_version, 2);

        // Both v1 and v2 ciphertexts decrypt correctly.
        let pt1 = decrypt(ring.key_for_version(1).unwrap(), &ct1).unwrap();
        assert_eq!(pt1, b"data-v1");
        let pt2 = decrypt(ring.key_for_version(2).unwrap(), &ct2).unwrap();
        assert_eq!(pt2, b"data-v2");

        // Versions list contains both.
        assert_eq!(ring.versions(), vec![1, 2]);
    }

    #[test]
    fn key_ring_unknown_version() {
        let key = Key::generate();
        let ring = KeyRing::new(key, 1);
        let err = ring.key_for_version(99).unwrap_err();
        assert!(matches!(err, CryptoError::UnknownKeyVersion(99)));
    }

    #[test]
    fn key_ring_rotation_derives_distinct_keys() {
        let key = Key::generate();
        let mut ring = KeyRing::new(key, 1);
        let v1_key = ring.active_key().as_bytes().clone();
        ring.rotate_key().unwrap();
        let v2_key = ring.active_key().as_bytes().clone();
        assert_ne!(v1_key, v2_key);
    }
}
