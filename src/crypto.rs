use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64, Encoding as _};
use ed25519_dalek::{Signer, Verifier};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, Zeroizing};

const IV_BYTES: usize = 12;
pub(crate) const TAG_BYTES: usize = 16;

/// Constant-time comparison of two byte slices.
/// Returns `true` if they are equal without leaking timing information
/// about which bytes differ.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// ---------- Error type ----------

#[derive(Debug, PartialEq, Eq)]
pub enum VeilError {
    /// Cryptographic operation failed (AEAD, DH, signatures, key derivation, RNG)
    Crypto(String),
    /// Data encoding/decoding error (base64, JSON)
    Encoding(String),
    /// Browser storage error (localStorage, `IndexedDB`)
    Storage(String),
    /// Network/HTTP error
    Network(String),
    /// Input validation failed
    Validation(String),
    /// Data format error (wrong sizes, missing fields, bad versions)
    Format(String),
    /// TOFU key pinning mismatch
    Tofu(String),
    /// Runtime environment not available
    Environment(String),
}

impl std::fmt::Display for VeilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto(msg)
            | Self::Encoding(msg)
            | Self::Storage(msg)
            | Self::Network(msg)
            | Self::Validation(msg)
            | Self::Format(msg)
            | Self::Tofu(msg)
            | Self::Environment(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for VeilError {}

impl VeilError {
    /// Return a static label for the error variant.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Crypto(_) => "Crypto",
            Self::Encoding(_) => "Encoding",
            Self::Storage(_) => "Storage",
            Self::Network(_) => "Network",
            Self::Validation(_) => "Validation",
            Self::Format(_) => "Format",
            Self::Tofu(_) => "Tofu",
            Self::Environment(_) => "Environment",
        }
    }
}

// ---------- Core functions ----------

/// Generate a new X25519 key pair. Returns (secret, public).
/// The secret is wrapped in `Zeroizing` and will be cleared on drop.
///
/// # Errors
///
/// Returns `VeilError` if the system RNG fails.
pub fn generate_key_pair() -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), VeilError> {
    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    random_bytes(&mut *secret_bytes)?;
    let secret = StaticSecret::from(*secret_bytes);
    let public = PublicKey::from(&secret);
    Ok((Zeroizing::new(secret.to_bytes()), public.to_bytes()))
}

/// Encode raw bytes to base64 (constant-time).
pub fn to_base64(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

/// Decode base64 to bytes (constant-time).
///
/// # Errors
///
/// Returns `VeilError` if the input is not valid base64.
pub fn from_base64(b64: &str) -> Result<Vec<u8>, VeilError> {
    Base64::decode_vec(b64).map_err(|e| VeilError::Encoding(format!("invalid base64: {e}")))
}

/// Perform X25519 Diffie-Hellman. Returns 32-byte shared secret.
///
/// # Errors
///
/// Returns `VeilError` if the peer's public key is a low-order point,
/// producing a non-contributory (all-zeros) shared secret (RFC 7748 §6).
pub fn dh(our_secret: &[u8; 32], their_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, VeilError> {
    let mut secret_copy = *our_secret;
    let secret = StaticSecret::from(secret_copy);
    secret_copy.zeroize();

    let public = PublicKey::from(*their_public);
    let shared = secret.diffie_hellman(&public);

    if !shared.was_contributory() {
        return Err(VeilError::Crypto("DH produced non-contributory output (low-order point)".into()));
    }

    Ok(Zeroizing::new(*shared.as_bytes()))
}

/// Generic HKDF-SHA256 key derivation.
///
/// # Errors
///
/// Returns `VeilError` if HKDF expansion fails (e.g. `out_len` too large).
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, VeilError> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .map_err(|e| VeilError::Crypto(format!("hkdf expand: {e}")))?;
    Ok(Zeroizing::new(okm))
}

/// Fill a buffer with cryptographically secure random bytes.
///
/// # Errors
///
/// Returns `VeilError` if the system RNG fails.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), VeilError> {
    getrandom::getrandom(buf).map_err(|e| VeilError::Crypto(format!("rng: {e}")))
}

/// Generate a random 32-byte key (for use as a DEK).
///
/// # Errors
///
/// Returns `VeilError` if the system RNG fails.
pub fn generate_random_key() -> Result<Zeroizing<[u8; 32]>, VeilError> {
    let mut key = Zeroizing::new([0u8; 32]);
    random_bytes(&mut *key)?;
    Ok(key)
}

/// Derive a 32-byte key via HKDF-SHA256, returning it as a zeroizing array.
///
/// # Errors
///
/// Returns `VeilError` if HKDF expansion fails.
pub fn hkdf_derive_key(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, VeilError> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *okm)
        .map_err(|e| VeilError::Crypto(format!("hkdf expand: {e}")))?;
    Ok(okm)
}

/// Encrypt with AES-256-GCM using a specific key and associated data.
/// Returns the ciphertext with the 12-byte nonce prepended.
///
/// # Errors
///
/// Returns `VeilError` if cipher initialization or encryption fails.
pub fn aead_encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, VeilError> {
    use aes_gcm::aead::Payload;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VeilError::Crypto(format!("cipher init: {e}")))?;

    let mut nonce_bytes = [0u8; IV_BYTES];
    random_bytes(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload { msg: plaintext, aad: ad };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| {
            nonce_bytes.zeroize();
            VeilError::Crypto(format!("encrypt: {e}"))
        })?;

    let mut out = Vec::with_capacity(IV_BYTES.saturating_add(ciphertext.len()));
    out.extend_from_slice(&nonce_bytes);
    nonce_bytes.zeroize();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt with AES-256-GCM. Nonce is the first 12 bytes of ciphertext.
///
/// # Errors
///
/// Returns `VeilError` if the ciphertext is too short, the key is wrong,
/// or the data has been tampered with.
pub fn aead_decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VeilError> {
    use aes_gcm::aead::Payload;

    if ciphertext.len() < IV_BYTES + TAG_BYTES {
        return Err(VeilError::Format("ciphertext too short".into()));
    }

    let (nonce_bytes, ct) = ciphertext.split_at(IV_BYTES);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VeilError::Crypto(format!("cipher init: {e}")))?;

    let payload = Payload { msg: ct, aad: ad };
    cipher
        .decrypt(nonce, payload)
        .map(Zeroizing::new)
        .map_err(|_| VeilError::Crypto("decrypt failed: wrong key or corrupted data".into()))
}

/// Encrypt with AES-256-GCM using a caller-provided nonce.
/// Returns ciphertext || tag (nonce is NOT prepended).
///
/// Used by streaming encryption where the nonce is derived from the
/// chunk index and a random prefix.
pub(crate) fn aead_encrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; IV_BYTES],
    plaintext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, VeilError> {
    use aes_gcm::aead::Payload;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VeilError::Crypto(format!("cipher init: {e}")))?;

    let nonce = Nonce::from_slice(nonce);
    let payload = Payload { msg: plaintext, aad: ad };
    cipher
        .encrypt(nonce, payload)
        .map_err(|e| VeilError::Crypto(format!("encrypt: {e}")))
}

/// Decrypt with AES-256-GCM using a caller-provided nonce.
/// Input is ciphertext || tag (no nonce prefix).
pub(crate) fn aead_decrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; IV_BYTES],
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VeilError> {
    use aes_gcm::aead::Payload;

    if ciphertext.len() < TAG_BYTES {
        return Err(VeilError::Format("ciphertext too short".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VeilError::Crypto(format!("cipher init: {e}")))?;

    let nonce = Nonce::from_slice(nonce);
    let payload = Payload { msg: ciphertext, aad: ad };
    cipher
        .decrypt(nonce, payload)
        .map(Zeroizing::new)
        .map_err(|_| VeilError::Crypto("decrypt failed: wrong key or corrupted data".into()))
}

// ---------- Ed25519 signing ----------

/// Generate an Ed25519 signing key pair. Returns `(secret, public)`.
/// The secret is wrapped in `Zeroizing` and will be cleared on drop.
///
/// # Errors
///
/// Returns `VeilError` if the system RNG fails.
pub fn generate_signing_key_pair() -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), VeilError> {
    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    random_bytes(&mut *secret_bytes)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    Ok((Zeroizing::new(signing_key.to_bytes()), verifying_key.to_bytes()))
    // signing_key: ZeroizeOnDrop — auto-zeroized here
}

/// Sign a message with an Ed25519 secret key.
/// Returns a 64-byte signature.
pub fn ed25519_sign(secret: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret);
    signing_key.sign(message).to_bytes()
    // signing_key: ZeroizeOnDrop — auto-zeroized here
}

/// Compute SHA-256 hash of the given data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Verify an Ed25519 signature.
///
/// # Errors
///
/// Returns `VeilError` if the signature is invalid or the public key is malformed.
pub fn ed25519_verify(
    public: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), VeilError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public)
        .map_err(|e| VeilError::Crypto(format!("invalid signing public key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key
        .verify(message, &sig)
        .map_err(|_| VeilError::Crypto("signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    // ---- AEAD ----

    #[test]
    fn aead_roundtrip() {
        let key = generate_random_key().unwrap();
        let ad = b"associated data";
        let ct = aead_encrypt(&key, b"hello world", ad).unwrap();
        let pt = aead_decrypt(&key, &ct, ad).unwrap();
        assert_eq!(*pt, b"hello world"[..]);
    }

    #[test]
    fn aead_different_nonces() {
        let key = generate_random_key().unwrap();
        let ad = b"test";
        let ct1 = aead_encrypt(&key, b"same message", ad).unwrap();
        let ct2 = aead_encrypt(&key, b"same message", ad).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn aead_bit_flip_detected() {
        let key = generate_random_key().unwrap();
        let ad = b"tamper test";
        let mut ct = aead_encrypt(&key, b"sensitive data", ad).unwrap();
        ct[14] ^= 0x01;
        let result = aead_decrypt(&key, &ct, ad);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "flipped bit must be detected");
    }

    #[test]
    fn aead_wrong_ad_detected() {
        let key = generate_random_key().unwrap();
        let ct = aead_encrypt(&key, b"data", b"correct ad").unwrap();
        let result = aead_decrypt(&key, &ct, b"wrong ad");
        assert!(matches!(result, Err(VeilError::Crypto(_))), "mismatched AD must be detected");
    }

    #[test]
    fn aead_truncated_ciphertext_rejected() {
        let key = generate_random_key().unwrap();
        let ct = aead_encrypt(&key, b"data", b"ad").unwrap();
        let result = aead_decrypt(&key, &ct[..20], b"ad");
        assert!(matches!(result, Err(VeilError::Format(_))), "truncated ciphertext must be Format error");
    }

    #[test]
    fn aead_wrong_key_fails() {
        let key1 = generate_random_key().unwrap();
        let key2 = generate_random_key().unwrap();
        let ad = b"test";
        let ct = aead_encrypt(&key1, b"secret", ad).unwrap();
        let result = aead_decrypt(&key2, &ct, ad);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "wrong key must fail decryption");
    }

    // ---- Key generation ----

    #[test]
    fn generate_key_pair_works() {
        let (secret1, public1) = generate_key_pair().unwrap();
        let (secret2, public2) = generate_key_pair().unwrap();
        assert_ne!(*secret1, *secret2);
        assert_ne!(public1, public2);
        assert!(dh(&secret1, &public1).is_ok());
    }

    #[test]
    fn generate_random_key_works() {
        let k1 = generate_random_key().unwrap();
        let k2 = generate_random_key().unwrap();
        assert_eq!(k1.len(), 32);
        assert_ne!(k1, k2);
        // Key must not be all zeros (catastrophic RNG failure)
        assert_ne!(*k1, [0u8; 32], "generated key must not be all zeros");
    }

    // ---- DH ----

    #[test]
    fn dh_symmetric() {
        let (alice_sec, alice_pub) = generate_key_pair().unwrap();
        let (bob_sec, bob_pub) = generate_key_pair().unwrap();
        let shared_ab = dh(&alice_sec, &bob_pub).unwrap();
        let shared_ba = dh(&bob_sec, &alice_pub).unwrap();
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn dh_rejects_low_order_point() {
        let (secret, _public) = generate_key_pair().unwrap();
        let zero_public = [0u8; 32];
        let result = dh(&secret, &zero_public);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "low-order point must be rejected");
    }

    // ---- HKDF ----

    #[test]
    fn hkdf_different_info_produces_different_keys() {
        let ikm = [0x42u8; 32];
        let out_a = hkdf_sha256(&ikm, None, b"context-a", 32).unwrap();
        let out_b = hkdf_sha256(&ikm, None, b"context-b", 32).unwrap();
        assert_ne!(out_a, out_b, "different info must produce different keys");
        let out_a2 = hkdf_sha256(&ikm, None, b"context-a", 32).unwrap();
        assert_eq!(out_a, out_a2);
        let out_c = hkdf_sha256(&[0x99u8; 32], None, b"context-a", 32).unwrap();
        assert_ne!(out_a, out_c, "different IKM must produce different keys");
    }

    #[test]
    fn hkdf_too_large_output_fails() {
        let ikm = [0x42u8; 32];
        // SHA-256 HKDF can produce at most 255 * 32 = 8160 bytes
        let result = hkdf_sha256(&ikm, None, b"info", 8161);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "oversized HKDF output must fail");
    }

    // ---- SHA-256 ----

    #[test]
    fn sha256_known_answer() {
        let hash = sha256(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
        assert_ne!(sha256(b"abc"), sha256(b"abd"));
    }

    // ---- Ed25519 ----

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let (secret, public) = generate_signing_key_pair().unwrap();
        let message = b"hello world";
        let sig = ed25519_sign(&secret, message);
        assert!(ed25519_verify(&public, message, &sig).is_ok());
    }

    #[test]
    fn ed25519_wrong_key_fails() {
        let (secret1, _pub1) = generate_signing_key_pair().unwrap();
        let (_secret2, pub2) = generate_signing_key_pair().unwrap();
        let sig = ed25519_sign(&secret1, b"message");
        let result = ed25519_verify(&pub2, b"message", &sig);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "wrong key must fail verification");
    }

    #[test]
    fn ed25519_tampered_message_fails() {
        let (secret, public) = generate_signing_key_pair().unwrap();
        let sig = ed25519_sign(&secret, b"original");
        let result = ed25519_verify(&public, b"tampered", &sig);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "tampered message must fail verification");
    }

    #[test]
    fn ed25519_different_messages_different_sigs() {
        let (secret, _public) = generate_signing_key_pair().unwrap();
        let sig1 = ed25519_sign(&secret, b"message-a");
        let sig2 = ed25519_sign(&secret, b"message-b");
        assert_ne!(sig1, sig2, "different messages must produce different signatures");
        let sig1b = ed25519_sign(&secret, b"message-a");
        assert_eq!(sig1, sig1b);
    }

    // ---- Base64 ----

    #[test]
    fn from_base64_rejects_invalid() {
        let result = from_base64("not valid base64!!!");
        assert!(matches!(result, Err(VeilError::Encoding(_))), "invalid base64 must be Encoding error");
        let result = from_base64("");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn base64_roundtrip() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = to_base64(&data);
        let decoded = from_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    // ---- AEAD edge cases ----

    #[test]
    fn aead_empty_plaintext_roundtrip() {
        let key = generate_random_key().unwrap();
        let ad = b"some context";
        let ct = aead_encrypt(&key, b"", ad).unwrap();
        // Empty plaintext still produces nonce(12) + tag(16) = 28 bytes
        assert_eq!(ct.len(), IV_BYTES + TAG_BYTES);
        let pt = aead_decrypt(&key, &ct, ad).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn aead_empty_ad_roundtrip() {
        let key = generate_random_key().unwrap();
        let ct = aead_encrypt(&key, b"data", b"").unwrap();
        let pt = aead_decrypt(&key, &ct, b"").unwrap();
        assert_eq!(*pt, b"data"[..]);
        // Empty AD still binds — using non-empty AD must fail
        let result = aead_decrypt(&key, &ct, b"non-empty");
        assert!(matches!(result, Err(VeilError::Crypto(_))),
            "non-empty AD must not decrypt ciphertext encrypted with empty AD");
    }

    #[test]
    fn aead_empty_plaintext_and_empty_ad() {
        let key = generate_random_key().unwrap();
        let ct = aead_encrypt(&key, b"", b"").unwrap();
        let pt = aead_decrypt(&key, &ct, b"").unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn aead_decrypt_empty_ciphertext_rejected() {
        let key = generate_random_key().unwrap();
        let result = aead_decrypt(&key, &[], b"ad");
        assert!(matches!(result, Err(VeilError::Format(_))),
            "empty ciphertext must be rejected");
    }

    // ---- AEAD with explicit nonce edge cases ----

    #[test]
    fn aead_with_nonce_empty_plaintext() {
        let key = generate_random_key().unwrap();
        let nonce = [0u8; IV_BYTES];
        let ct = aead_encrypt_with_nonce(&key, &nonce, b"", b"ad").unwrap();
        assert_eq!(ct.len(), TAG_BYTES); // No nonce prefix, just tag
        let pt = aead_decrypt_with_nonce(&key, &nonce, &ct, b"ad").unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn aead_with_nonce_too_short_rejected() {
        let key = generate_random_key().unwrap();
        let nonce = [0u8; IV_BYTES];
        // Less than TAG_BYTES
        let result = aead_decrypt_with_nonce(&key, &nonce, &[0u8; 10], b"ad");
        assert!(matches!(result, Err(VeilError::Format(_))),
            "ciphertext shorter than tag must be rejected");
    }
}
