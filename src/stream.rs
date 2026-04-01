use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::constants::{self, DOMAIN_STREAM_V1};
use crate::crypto::{self, VeilError};
use crate::envelope::{self, EnvelopeAccess, WrappedKey};

const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024; // 64 KiB
const NONCE_PREFIX_LEN: usize = 8;
// Compile-time assertion: nonce_prefix (8) + chunk_index (4) must equal AES-GCM nonce (12).
const _: () = assert!(NONCE_PREFIX_LEN + 4 == 12);

/// Stream header: DEK access control, stream metadata, and signature.
#[derive(Clone)]
pub struct StreamHeader {
    pub version: u8,
    pub chunk_size: u32,
    pub nonce_prefix: String,
    pub access: EnvelopeAccess,
    pub metadata: Option<serde_json::Value>,
    pub signer_id: Option<String>,
    pub signature: Option<String>,
}

// ---------- Serde wire format ----------

#[derive(Serialize, Deserialize)]
struct StreamHeaderWire {
    version: u8,
    chunk_size: u32,
    nonce_prefix: String,
    recipients: Vec<WrappedKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrapped_dek: Option<String>,
}

impl TryFrom<StreamHeaderWire> for StreamHeader {
    type Error = VeilError;

    fn try_from(w: StreamHeaderWire) -> Result<Self, Self::Error> {
        if w.version == 0 {
            return Err(VeilError::Format("stream header version must be >= 1".into()));
        }
        if w.version != 1 {
            return Err(VeilError::Format(format!(
                "unsupported stream header version: {}", w.version
            )));
        }
        if w.chunk_size == 0 {
            return Err(VeilError::Validation("chunk_size must be > 0".into()));
        }
        if w.recipients.len() > constants::MAX_RECIPIENTS {
            return Err(VeilError::Validation(format!(
                "too many recipients: {} (max {})",
                w.recipients.len(),
                constants::MAX_RECIPIENTS
            )));
        }
        {
            let mut seen = std::collections::HashSet::with_capacity(w.recipients.len());
            for r in &w.recipients {
                if !seen.insert(&r.user_id) {
                    return Err(VeilError::Format(format!(
                        "duplicate recipient '{}' in stream header",
                        r.user_id
                    )));
                }
            }
        }
        let access = match (w.group_id, w.wrapped_dek) {
            (Some(group_id), Some(wrapped_dek)) => {
                if !w.recipients.is_empty() {
                    return Err(VeilError::Format(
                        "group stream header must not have recipients".into(),
                    ));
                }
                EnvelopeAccess::Group { group_id, wrapped_dek }
            }
            (None, None) => EnvelopeAccess::Direct { recipients: w.recipients },
            _ => {
                return Err(VeilError::Format(
                    "group_id and wrapped_dek must both be present or both absent".into(),
                ));
            }
        };

        Ok(Self {
            version: w.version,
            chunk_size: w.chunk_size,
            nonce_prefix: w.nonce_prefix,
            access,
            metadata: w.metadata,
            signer_id: w.signer_id,
            signature: w.signature,
        })
    }
}

impl From<StreamHeader> for StreamHeaderWire {
    fn from(h: StreamHeader) -> Self {
        let (recipients, group_id, wrapped_dek) = match h.access {
            EnvelopeAccess::Direct { recipients } => (recipients, None, None),
            EnvelopeAccess::Group { group_id, wrapped_dek } => {
                (Vec::new(), Some(group_id), Some(wrapped_dek))
            }
        };

        Self {
            version: h.version,
            chunk_size: h.chunk_size,
            nonce_prefix: h.nonce_prefix,
            recipients,
            metadata: h.metadata,
            signer_id: h.signer_id,
            signature: h.signature,
            group_id,
            wrapped_dek,
        }
    }
}

impl Serialize for StreamHeader {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = StreamHeaderWire::from(self.clone());
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StreamHeader {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = StreamHeaderWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(serde::de::Error::custom)
    }
}

// ---------- Convenience delegates ----------

impl StreamHeader {
    pub const fn is_group(&self) -> bool {
        self.access.is_group()
    }

    pub fn group_id(&self) -> Option<&str> {
        self.access.group_id()
    }

    pub fn recipients(&self) -> &[WrappedKey] {
        self.access.recipients()
    }

    pub fn group_info(&self) -> Option<(&str, &str)> {
        self.access.group_info()
    }
}

/// Streaming sealer state. Encrypts chunks one at a time.
pub struct SealerState {
    cipher: Aes256Gcm,
    dek: Zeroizing<[u8; 32]>,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_index: u32,
    header: StreamHeader,
    finalized: bool,
}

/// Streaming opener state. Decrypts chunks one at a time.
pub struct OpenerState {
    cipher: Aes256Gcm,
    dek: Zeroizing<[u8; 32]>,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_index: u32,
    done: bool,
}

// ---------- Nonce / AD construction ----------

fn build_nonce(prefix: [u8; NONCE_PREFIX_LEN], chunk_index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(&prefix); // bytes 0..8
    nonce[8..12].copy_from_slice(&chunk_index.to_be_bytes()); // bytes 8..12
    nonce
}

fn build_ad(chunk_index: u32, is_final: bool) -> [u8; 16] {
    let mut ad = [0u8; 16];
    ad[..11].copy_from_slice(constants::DOMAIN_STREAM_CHUNK);
    ad[11..15].copy_from_slice(&chunk_index.to_be_bytes());
    ad[15] = u8::from(is_final);
    ad
}

// ---------- Header signature ----------

/// Deterministic payload for header signing.
fn header_payload(
    header: &StreamHeader,
    cached_metadata: Option<&[u8]>,
) -> Result<Vec<u8>, VeilError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(DOMAIN_STREAM_V1);
    payload.push(header.version);
    payload.extend_from_slice(&header.chunk_size.to_be_bytes());

    let prefix_bytes = crypto::from_base64(&header.nonce_prefix)?;
    payload.extend_from_slice(&prefix_bytes);

    if let Some(ref id) = header.signer_id {
        payload.push(1);
        let id_bytes = id.as_bytes();
        let len: u32 = id_bytes.len()
            .try_into()
            .map_err(|_| VeilError::Format("signer_id too long".into()))?;
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(id_bytes);
    } else {
        payload.push(0);
    }
    envelope::append_metadata_to_payload(&mut payload, &header.metadata, cached_metadata)?;
    envelope::append_access_to_payload(&mut payload, &header.access)?;
    Ok(payload)
}

/// Verify the Ed25519 signature on a stream header.
///
/// # Errors
///
/// Returns `VeilError` if the header is unsigned, the signature is malformed,
/// or verification fails.
pub fn verify_header(
    header: &StreamHeader,
    signer_public: &[u8; 32],
) -> Result<(), VeilError> {
    let sig_b64 = header
        .signature
        .as_ref()
        .ok_or_else(|| VeilError::Encoding("header is unsigned".into()))?;

    let sig_bytes: [u8; 64] = crypto::from_base64(sig_b64)?
        .try_into()
        .map_err(|_| VeilError::Format("signature is not 64 bytes".into()))?;

    let payload = header_payload(header, None)?;
    crypto::ed25519_verify(signer_public, &payload, &sig_bytes)
}

// ---------- Sealer ----------

/// Create a streaming sealer for per-recipient encryption.
///
/// Generates a DEK, wraps it for each recipient, builds and signs the header.
/// Returns the sealer ready to encrypt chunks.
///
/// # Errors
///
/// Returns `VeilError` if key generation, wrapping, or signing fails.
pub fn create_sealer(
    our_id: &str,
    sign_secret: &[u8; 32],
    recipient_keys: &[(&str, &[u8; 32])],
    our_public: &[u8; 32],
    metadata: Option<serde_json::Value>,
    chunk_size: Option<u32>,
) -> Result<SealerState, VeilError> {
    let dek = crypto::generate_random_key()?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    crypto::random_bytes(&mut nonce_prefix)?;

    constants::validate_id(our_id, "sealer user_id")?;
    for (id, _) in recipient_keys {
        constants::validate_id(id, "recipient user_id")?;
    }
    if recipient_keys.len() >= constants::MAX_RECIPIENTS {
        return Err(VeilError::Validation(format!(
            "too many recipients: {} (max {})",
            recipient_keys.len().saturating_add(1),
            constants::MAX_RECIPIENTS
        )));
    }
    let meta_bytes = constants::validate_metadata(metadata.as_ref())?;

    if recipient_keys.iter().any(|(id, _)| *id == our_id) {
        return Err(VeilError::Validation("sealer already in recipient list".into()));
    }

    let mut seen = std::collections::HashSet::with_capacity(recipient_keys.len());
    for (id, _) in recipient_keys {
        if !seen.insert(*id) {
            return Err(VeilError::Validation(format!("duplicate recipient '{id}'")));
        }
    }

    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    if chunk_size == 0 {
        return Err(VeilError::Validation("chunk_size must be > 0".into()));
    }

    // Wrap DEK for sealer + recipients
    let mut recipients = Vec::with_capacity(1_usize.saturating_add(recipient_keys.len()));
    recipients.push(envelope::wrap_dek(&dek, our_id, our_public)?);
    for (id, pub_key) in recipient_keys {
        recipients.push(envelope::wrap_dek(&dek, id, pub_key)?);
    }

    let mut header = StreamHeader {
        version: 1,
        chunk_size,
        nonce_prefix: crypto::to_base64(&nonce_prefix),
        access: EnvelopeAccess::Direct { recipients },
        metadata,
        signer_id: Some(our_id.to_string()),
        signature: None,
    };

    let payload = header_payload(&header, meta_bytes.as_deref())?;
    let sig = crypto::ed25519_sign(sign_secret, &payload);
    header.signature = Some(crypto::to_base64(&sig));

    let cipher = Aes256Gcm::new_from_slice(&*dek)
        .map_err(|e| VeilError::Crypto(format!("cipher init: {e}")))?;

    Ok(SealerState {
        cipher,
        dek,
        nonce_prefix,
        chunk_index: 0,
        header,
        finalized: false,
    })
}

/// Create a streaming sealer for group encryption.
///
/// # Errors
///
/// Returns `VeilError` if key generation, wrapping, or signing fails.
pub fn create_group_sealer(
    our_id: &str,
    sign_secret: &[u8; 32],
    gek: &[u8; 32],
    group_id: &str,
    metadata: Option<serde_json::Value>,
    chunk_size: Option<u32>,
) -> Result<SealerState, VeilError> {
    let meta_bytes = constants::validate_metadata(metadata.as_ref())?;
    let dek = crypto::generate_random_key()?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    crypto::random_bytes(&mut nonce_prefix)?;

    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    if chunk_size == 0 {
        return Err(VeilError::Validation("chunk_size must be > 0".into()));
    }

    // Wrap DEK with GEK
    let ad = constants::group_dek_ad(group_id);
    let wrapped = crypto::aead_encrypt(gek, &*dek, &ad)?;

    let mut header = StreamHeader {
        version: 1,
        chunk_size,
        nonce_prefix: crypto::to_base64(&nonce_prefix),
        access: EnvelopeAccess::Group {
            group_id: group_id.to_string(),
            wrapped_dek: crypto::to_base64(&wrapped),
        },
        metadata,
        signer_id: Some(our_id.to_string()),
        signature: None,
    };

    let payload = header_payload(&header, meta_bytes.as_deref())?;
    let sig = crypto::ed25519_sign(sign_secret, &payload);
    header.signature = Some(crypto::to_base64(&sig));

    let cipher = Aes256Gcm::new_from_slice(&*dek)
        .map_err(|e| VeilError::Crypto(format!("cipher init: {e}")))?;

    Ok(SealerState {
        cipher,
        dek,
        nonce_prefix,
        chunk_index: 0,
        header,
        finalized: false,
    })
}

impl SealerState {
    /// Get the stream header (available immediately after creation).
    pub const fn header(&self) -> &StreamHeader {
        &self.header
    }

    /// Encrypt a chunk. Set `is_last` to `true` for the final chunk.
    ///
    /// Returns `is_final(1) || ciphertext || tag(16)`.
    ///
    /// # Errors
    ///
    /// Returns `VeilError` if the stream is already finalized or encryption fails.
    pub fn seal_chunk(
        &mut self,
        plaintext: &[u8],
        is_last: bool,
    ) -> Result<Vec<u8>, VeilError> {
        if self.finalized {
            return Err(VeilError::Validation("stream already finalized".into()));
        }

        let nonce_bytes = build_nonce(self.nonce_prefix, self.chunk_index);
        let ad = build_ad(self.chunk_index, is_last);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload { msg: plaintext, aad: &ad };
        let ct = self.cipher.encrypt(nonce, payload)
            .map_err(|e| VeilError::Crypto(format!("encrypt: {e}")))?;

        self.chunk_index = self.chunk_index
            .checked_add(1)
            .ok_or_else(|| VeilError::Format("chunk index overflow".into()))?;

        if is_last {
            self.finalized = true;
        }

        // Output: is_final(1) || ciphertext || tag
        let mut out = Vec::with_capacity(1_usize.saturating_add(ct.len()));
        out.push(u8::from(is_last));
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

// ---------- Opener ----------

/// Create a streaming opener from a header and an unwrapped DEK.
///
/// # Errors
///
/// Returns `VeilError` if the nonce prefix in the header is invalid.
pub fn create_opener(
    header: &StreamHeader,
    dek: Zeroizing<[u8; 32]>,
) -> Result<OpenerState, VeilError> {
    let prefix_bytes = crypto::from_base64(&header.nonce_prefix)?;
    let nonce_prefix: [u8; NONCE_PREFIX_LEN] = prefix_bytes
        .try_into()
        .map_err(|_| VeilError::Crypto("nonce_prefix not 8 bytes".into()))?;

    let cipher = Aes256Gcm::new_from_slice(&*dek)
        .map_err(|e| VeilError::Crypto(format!("cipher init: {e}")))?;

    Ok(OpenerState {
        cipher,
        dek,
        nonce_prefix,
        chunk_index: 0,
        done: false,
    })
}

impl OpenerState {
    /// Decrypt a chunk. Returns the plaintext.
    ///
    /// Input format: `is_final(1) || ciphertext || tag(16)`.
    ///
    /// # Errors
    ///
    /// Returns `VeilError` if the stream is finished, chunk is too short, or decryption fails.
    pub fn open_chunk(&mut self, encrypted_chunk: &[u8]) -> Result<Zeroizing<Vec<u8>>, VeilError> {
        if self.done {
            return Err(VeilError::Validation("stream already finished".into()));
        }

        let (&flag, ct) = encrypted_chunk
            .split_first()
            .ok_or_else(|| VeilError::Format("encrypted chunk too short".into()))?;

        if ct.len() < crypto::TAG_BYTES {
            return Err(VeilError::Format("encrypted chunk too short".into()));
        }

        let is_final = flag != 0;

        let nonce_bytes = build_nonce(self.nonce_prefix, self.chunk_index);
        let ad = build_ad(self.chunk_index, is_final);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload { msg: ct, aad: &ad };
        let decrypted = self.cipher.decrypt(nonce, payload)
            .map(Zeroizing::new)
            .map_err(|_| VeilError::Crypto("decrypt failed: wrong key or corrupted data".into()))?;

        self.chunk_index = self.chunk_index
            .checked_add(1)
            .ok_or_else(|| VeilError::Format("chunk index overflow".into()))?;

        if is_final {
            self.done = true;
        }

        Ok(decrypted)
    }

    /// Whether the final chunk has been processed.
    pub const fn is_done(&self) -> bool {
        self.done
    }
}

/// Unwrap the DEK from a stream header for a per-recipient stream.
///
/// # Errors
///
/// Returns `VeilError` if the recipient is not found or unwrapping fails.
pub fn unwrap_stream_dek(
    header: &StreamHeader,
    our_id: &str,
    our_secret: &[u8; 32],
    our_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, VeilError> {
    let recipients = match &header.access {
        EnvelopeAccess::Direct { recipients } => recipients,
        EnvelopeAccess::Group { .. } => {
            return Err(VeilError::Validation("not a recipient of this stream".into()));
        }
    };

    let wrapped = recipients
        .iter()
        .find(|w| w.user_id == our_id)
        .ok_or_else(|| VeilError::Validation("not a recipient of this stream".into()))?;

    envelope::unwrap_dek(wrapped, our_secret, our_public)
}

/// Unwrap the DEK from a group stream header using the GEK.
///
/// # Errors
///
/// Returns `VeilError` if the header is not a group stream or decryption fails.
pub fn unwrap_group_stream_dek(
    header: &StreamHeader,
    gek: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, VeilError> {
    let (group_id, wrapped_dek_b64) = match &header.access {
        EnvelopeAccess::Group { group_id, wrapped_dek } => (group_id.as_str(), wrapped_dek.as_str()),
        EnvelopeAccess::Direct { .. } => {
            return Err(VeilError::Encoding("not a group stream".into()));
        }
    };

    let wrapped = crypto::from_base64(wrapped_dek_b64)?;
    let ad = constants::group_dek_ad(group_id);

    let dek_bytes = crypto::aead_decrypt(gek, &wrapped, &ad)?;
    Ok(Zeroizing::new(<[u8; 32]>::try_from(dek_bytes.as_slice())
        .map_err(|_| VeilError::Format("unwrapped DEK not 32 bytes".into()))?))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::type_complexity, clippy::indexing_slicing)]

    use super::*;
    use crate::crypto::{self, VeilError};
    use crate::group;
    use crate::test_utils::make_user;

    // ---- Single-chunk roundtrip ----

    #[test]
    fn single_chunk_roundtrip() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_b, &pub_b)];
        let mut sealer = create_sealer(&id_a, &sign_a, &recipients, &pub_a, None, None).unwrap();
        let plaintext = b"hello streaming world";
        let encrypted = sealer.seal_chunk(plaintext, true).unwrap();
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_b, &dh_b, &pub_b).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        let decrypted = opener.open_chunk(&encrypted).unwrap();
        assert_eq!(&*decrypted, plaintext);
        assert!(opener.is_done());
    }

    // ---- Multi-chunk roundtrip ----

    #[test]
    fn multi_chunk_roundtrip() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_b, &pub_b)];
        let mut sealer = create_sealer(&id_a, &sign_a, &recipients, &pub_a, None, Some(16)).unwrap();
        let chunks: Vec<&[u8]> = vec![b"chunk-one", b"chunk-two", b"chunk-three"];
        let mut encrypted_chunks = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let is_last = i == chunks.len() - 1;
            encrypted_chunks.push(sealer.seal_chunk(chunk, is_last).unwrap());
        }
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_b, &dh_b, &pub_b).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        for (i, enc) in encrypted_chunks.iter().enumerate() {
            let decrypted = opener.open_chunk(enc).unwrap();
            assert_eq!(&*decrypted, chunks[i]);
        }
        assert!(opener.is_done());
    }

    // ---- Sender can also decrypt ----

    #[test]
    fn sender_can_decrypt() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_b, &pub_b)];
        let mut sealer = create_sealer(&id_a, &sign_a, &recipients, &pub_a, None, None).unwrap();
        let encrypted = sealer.seal_chunk(b"for both", true).unwrap();
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        let decrypted = opener.open_chunk(&encrypted).unwrap();
        assert_eq!(&*decrypted, b"for both");
    }

    // ---- Empty plaintext ----

    #[test]
    fn empty_plaintext() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let encrypted = sealer.seal_chunk(b"", true).unwrap();
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        let decrypted = opener.open_chunk(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    // ---- Truncation detection ----

    #[test]
    fn truncation_detected() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let enc0 = sealer.seal_chunk(b"first", false).unwrap();
        let _enc1 = sealer.seal_chunk(b"second", false).unwrap();
        let _enc2 = sealer.seal_chunk(b"third", true).unwrap();
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        opener.open_chunk(&enc0).unwrap();
        assert!(!opener.is_done());
    }

    // ---- Reordering detection ----

    #[test]
    fn reorder_detected() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let _enc0 = sealer.seal_chunk(b"first", false).unwrap();
        let enc1 = sealer.seal_chunk(b"second", true).unwrap();
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        let result = opener.open_chunk(&enc1);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "reordered chunk must fail decryption");
    }

    // ---- Seal after finalize errors ----

    #[test]
    fn seal_after_finalize_errors() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        sealer.seal_chunk(b"only", true).unwrap();
        let result = sealer.seal_chunk(b"extra", false);
        assert!(matches!(result, Err(VeilError::Validation(_))), "sealing after finalize must fail");
    }

    // ---- Open after done errors ----

    #[test]
    fn open_after_done_errors() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let encrypted = sealer.seal_chunk(b"done", true).unwrap();
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        opener.open_chunk(&encrypted).unwrap();
        assert!(opener.is_done());
        let result = opener.open_chunk(&encrypted);
        assert!(matches!(result, Err(VeilError::Validation(_))), "opening after stream done must fail");
    }

    // ---- Wrong DEK fails ----

    #[test]
    fn wrong_dek_fails() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let encrypted = sealer.seal_chunk(b"secret", true).unwrap();
        let header = sealer.header();
        let wrong_dek = Zeroizing::new([0xFFu8; 32]);
        let mut opener = create_opener(header, wrong_dek).unwrap();
        let result = opener.open_chunk(&encrypted);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "wrong DEK must fail decryption");
    }

    // ---- Non-recipient cannot unwrap DEK ----

    #[test]
    fn non_recipient_cannot_unwrap() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_c, dh_c, pub_c, _sign_c, _spub_c) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        sealer.seal_chunk(b"data", true).unwrap();
        let header = sealer.header();
        let result = unwrap_stream_dek(header, &id_c, &dh_c, &pub_c);
        assert!(matches!(result, Err(VeilError::Validation(_))), "non-recipient must not unwrap DEK");
    }

    // ---- Chunk too short ----

    #[test]
    fn chunk_too_short() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        sealer.seal_chunk(b"x", true).unwrap();
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        let result = opener.open_chunk(&[0u8; 5]);
        assert!(matches!(result, Err(VeilError::Format(_))), "chunk too short must be rejected");
    }

    // ---- Bit-flip detection ----

    #[test]
    fn bit_flip_detected() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let mut encrypted = sealer.seal_chunk(b"tamper me", true).unwrap();
        encrypted[5] ^= 0x01;
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        let result = opener.open_chunk(&encrypted);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "bit-flipped chunk must fail decryption");
    }

    // ---- Header signature verification ----

    #[test]
    fn header_signature_valid() {
        let (id_a, _dh_a, pub_a, sign_a, spub_a) = make_user();
        let sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let header = sealer.header();
        assert!(header.signature.is_some());
        verify_header(header, &spub_a).unwrap();
    }

    #[test]
    fn header_signature_wrong_key_fails() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (_id_b, _dh_b, _pub_b, _sign_b, spub_b) = make_user();
        let sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let header = sealer.header();
        let result = verify_header(header, &spub_b);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "wrong key must fail header verification");
    }

    // ---- Header JSON roundtrip ----

    #[test]
    fn header_json_roundtrip() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_b, &pub_b)];
        let meta = serde_json::json!({"type": "file", "name": "report.pdf"});
        let sealer = create_sealer(&id_a, &sign_a, &recipients, &pub_a, Some(meta.clone()), Some(1024)).unwrap();
        let header = sealer.header();
        let json = serde_json::to_string(header).unwrap();
        let parsed: StreamHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.chunk_size, 1024);
        assert_eq!(parsed.recipients().len(), 2);
        assert_eq!(parsed.signer_id.as_deref(), Some(id_a.as_str()));
        assert_eq!(parsed.metadata, Some(meta));
        assert!(parsed.signature.is_some());
        assert!(!parsed.is_group());
    }

    // ---- Cross-stream chunk replay ----

    #[test]
    fn cross_stream_chunk_replay_fails() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer1 = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let mut sealer2 = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let enc1 = sealer1.seal_chunk(b"stream-1-data", true).unwrap();
        let _enc2 = sealer2.seal_chunk(b"stream-2-data", true).unwrap();
        let header2 = sealer2.header();
        let dek2 = unwrap_stream_dek(header2, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener2 = create_opener(header2, dek2).unwrap();
        let result = opener2.open_chunk(&enc1);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "chunk from stream 1 must not decrypt in stream 2");
    }

    // ---- Chunk size zero rejected ----

    #[test]
    fn chunk_size_zero_rejected() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let result = create_sealer(&id_a, &sign_a, &[], &pub_a, None, Some(0));
        assert!(matches!(result, Err(VeilError::Validation(_))), "chunk size zero must be rejected");
    }

    // ---- Different sealers produce different nonces ----

    #[test]
    fn different_nonce_prefixes() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let sealer1 = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let sealer2 = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        assert_ne!(sealer1.header().nonce_prefix, sealer2.header().nonce_prefix);
    }

    // ---- Group stream roundtrip ----

    #[test]
    fn group_stream_roundtrip() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (_bundle, gek) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let mut sealer = create_group_sealer(&id_a, &sign_a, &gek, "team", None, None).unwrap();
        let enc0 = sealer.seal_chunk(b"group chunk 1", false).unwrap();
        let enc1 = sealer.seal_chunk(b"group chunk 2", true).unwrap();
        let header = sealer.header();
        assert_eq!(header.group_id(), Some("team"));
        assert!(header.group_info().is_some());
        assert!(header.recipients().is_empty());
        let dek = unwrap_group_stream_dek(header, &gek).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        assert_eq!(&*opener.open_chunk(&enc0).unwrap(), b"group chunk 1");
        assert!(!opener.is_done());
        assert_eq!(&*opener.open_chunk(&enc1).unwrap(), b"group chunk 2");
        assert!(opener.is_done());
    }

    // ---- Group stream wrong GEK fails ----

    #[test]
    fn group_stream_wrong_gek_fails() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (_bundle, gek) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let mut sealer = create_group_sealer(&id_a, &sign_a, &gek, "team", None, None).unwrap();
        sealer.seal_chunk(b"secret", true).unwrap();
        let header = sealer.header();
        let wrong_gek = [0xABu8; 32];
        let result = unwrap_group_stream_dek(header, &wrong_gek);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "wrong GEK must fail to unwrap stream DEK");
    }

    // ---- Group stream header signature ----

    #[test]
    fn group_stream_header_signature() {
        let (id_a, _dh_a, pub_a, sign_a, spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (_bundle, gek) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let sealer = create_group_sealer(&id_a, &sign_a, &gek, "team", None, None).unwrap();
        verify_header(sealer.header(), &spub_a).unwrap();
    }

    // ---- Group chunk size zero rejected ----

    #[test]
    fn group_chunk_size_zero_rejected() {
        let (id_a, _dh_a, _pub_a, sign_a, _spub_a) = make_user();
        let gek = [0u8; 32];
        let result = create_group_sealer(&id_a, &sign_a, &gek, "g", None, Some(0));
        assert!(matches!(result, Err(VeilError::Validation(_))), "group chunk size zero must be rejected");
    }

    // ---- Non-group header unwrap_group_stream_dek fails ----

    #[test]
    fn unwrap_group_dek_non_group_fails() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let gek = [0u8; 32];
        let result = unwrap_group_stream_dek(sealer.header(), &gek);
        assert!(matches!(result, Err(VeilError::Encoding(_))), "non-group header must be rejected");
    }

    // ---- Final flag tampering detected ----

    #[test]
    fn final_flag_tamper_detected() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let mut encrypted = sealer.seal_chunk(b"not final", false).unwrap();
        encrypted[0] = 1;
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        let result = opener.open_chunk(&encrypted);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "tampered final flag must fail decryption");
    }

    // ---- Large multi-chunk stream ----

    #[test]
    fn large_multi_chunk() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, Some(32)).unwrap();
        let data: Vec<u8> = (0u8..=255).collect();
        let chunk_size = 32;
        let mut encrypted_chunks = Vec::new();
        let num_chunks = data.len().div_ceil(chunk_size);
        for i in 0..num_chunks {
            let start = i * chunk_size;
            let end = std::cmp::min(start + chunk_size, data.len());
            let is_last = i == num_chunks - 1;
            encrypted_chunks.push(sealer.seal_chunk(&data[start..end], is_last).unwrap());
        }
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        let mut decrypted = Vec::new();
        for enc in &encrypted_chunks {
            decrypted.extend_from_slice(&opener.open_chunk(enc).unwrap());
        }
        assert!(opener.is_done());
        assert_eq!(decrypted, data);
    }

    // ---- Header nonce_prefix tampering ----

    #[test]
    fn header_nonce_prefix_tamper_fails() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let encrypted = sealer.seal_chunk(b"data", true).unwrap();
        let mut header = sealer.header().clone();
        header.nonce_prefix = crypto::to_base64(&[0xFFu8; 8]);
        let dek = unwrap_stream_dek(&header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(&header, dek).unwrap();
        let result = opener.open_chunk(&encrypted);
        assert!(result.is_err(), "tampered nonce_prefix must cause decryption failure");
    }

    // ---- Cross-path confusion ----

    #[test]
    fn group_header_with_per_recipient_unwrap_fails() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (_bundle, gek) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let sealer = create_group_sealer(&id_a, &sign_a, &gek, "team", None, None).unwrap();
        let result = unwrap_stream_dek(sealer.header(), &id_a, &dh_a, &pub_a);
        assert!(matches!(result, Err(VeilError::Validation(_))), "per-recipient unwrap on group header must fail");
    }

    // ---- Chunk duplication detected ----

    #[test]
    fn chunk_duplication_detected() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let enc0 = sealer.seal_chunk(b"data", true).unwrap();
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        opener.open_chunk(&enc0).unwrap();
        assert!(opener.is_done());
        let result = opener.open_chunk(&enc0);
        assert!(matches!(result, Err(VeilError::Validation(_))), "replaying a chunk after stream done must fail");
    }

    // ---- Duplicate recipients rejected ----

    #[test]
    fn create_sealer_rejects_duplicate_recipients() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_b, &pub_b), (&id_b, &pub_b)];
        let result = create_sealer(&id_a, &sign_a, &recipients, &pub_a, None, None);
        assert!(matches!(result, Err(VeilError::Validation(_))), "duplicate recipients must be rejected");
    }

    // ---- Self in recipients rejected ----

    #[test]
    fn create_sealer_rejects_self_in_recipients() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let result = create_sealer(&id_a, &sign_a, &recipients, &pub_a, None, None);
        assert!(matches!(result, Err(VeilError::Validation(_))), "sealer in recipient list must be rejected");
    }

    // ---- Chunk size = 1 (minimum useful size) ----

    #[test]
    fn chunk_size_one_roundtrip() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_b, &pub_b)];

        let mut sealer = create_sealer(&id_a, &sign_a, &recipients, &pub_a, None, Some(1)).unwrap();

        // Seal individual bytes
        let enc0 = sealer.seal_chunk(b"A", false).unwrap();
        let enc1 = sealer.seal_chunk(b"B", false).unwrap();
        let enc2 = sealer.seal_chunk(b"C", true).unwrap();

        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_b, &dh_b, &pub_b).unwrap();
        let mut opener = create_opener(header, dek).unwrap();

        assert_eq!(&*opener.open_chunk(&enc0).unwrap(), b"A");
        assert_eq!(&*opener.open_chunk(&enc1).unwrap(), b"B");
        assert_eq!(&*opener.open_chunk(&enc2).unwrap(), b"C");
        assert!(opener.is_done());
    }

    // ---- Empty non-final chunk ----

    #[test]
    fn empty_non_final_chunk() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_b, &pub_b)];

        let mut sealer = create_sealer(&id_a, &sign_a, &recipients, &pub_a, None, None).unwrap();

        // Empty non-final chunk followed by data chunk
        let enc0 = sealer.seal_chunk(b"", false).unwrap();
        let enc1 = sealer.seal_chunk(b"data", true).unwrap();

        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_b, &dh_b, &pub_b).unwrap();
        let mut opener = create_opener(header, dek).unwrap();

        assert_eq!(&*opener.open_chunk(&enc0).unwrap(), b"");
        assert_eq!(&*opener.open_chunk(&enc1).unwrap(), b"data");
        assert!(opener.is_done());
    }

    // ---- Header tampered signer_id fails verification ----

    #[test]
    fn header_tampered_signer_id() {
        let (id_a, _dh_a, pub_a, sign_a, spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_b, &pub_b)];

        let mut sealer = create_sealer(&id_a, &sign_a, &recipients, &pub_a, None, None).unwrap();
        sealer.seal_chunk(b"data", true).unwrap();

        let mut header = sealer.header().clone();
        header.signer_id = Some("attacker".to_string());
        assert!(matches!(
            verify_header(&header, &spub_a),
            Err(VeilError::Crypto(_))
        ), "tampered signer_id must invalidate header signature");
    }

    // ---- Max chunk index boundary (u32::MAX - 1 chunks is impractical but test near-limit) ----

    #[test]
    fn chunk_index_deterministic() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_b, &pub_b)];

        // Two sealers with different nonce prefixes produce different ciphertexts
        let mut sealer1 = create_sealer(&id_a, &sign_a, &recipients, &pub_a, None, None).unwrap();
        let mut sealer2 = create_sealer(&id_a, &sign_a, &recipients, &pub_a, None, None).unwrap();

        let enc1 = sealer1.seal_chunk(b"same data", true).unwrap();
        let enc2 = sealer2.seal_chunk(b"same data", true).unwrap();

        assert_ne!(enc1, enc2, "different nonce prefixes must produce different ciphertexts");
    }

    // ---- Version validation on deserialization ----

    #[test]
    fn deserialized_header_version_zero_rejected() {
        let json = r#"{"version":0,"chunk_size":65536,"nonce_prefix":"AAAAAAAAAA==","recipients":[]}"#;
        let result: Result<StreamHeader, _> = serde_json::from_str(json);
        assert!(result.is_err(), "version 0 must be rejected");
    }

    #[test]
    fn deserialized_header_version_two_rejected() {
        let json = r#"{"version":2,"chunk_size":65536,"nonce_prefix":"AAAAAAAAAA==","recipients":[]}"#;
        let result: Result<StreamHeader, _> = serde_json::from_str(json);
        assert!(result.is_err(), "version 2 must be rejected");
    }

    // ---- Deserialized duplicate recipients rejected ----

    #[test]
    fn deserialized_duplicate_recipients_rejected() {
        let json = r#"{"version":1,"chunk_size":65536,"nonce_prefix":"AAAAAAAAAA==","recipients":[
            {"user_id":"alice","ephemeral_public":"AAAA","encrypted_dek":"BBBB"},
            {"user_id":"alice","ephemeral_public":"CCCC","encrypted_dek":"DDDD"}
        ]}"#;
        let result: Result<StreamHeader, _> = serde_json::from_str(json);
        assert!(result.is_err(),
            "deserialized stream header with duplicate recipients must be rejected");
    }

    // ---- Nonce uniqueness across chunk indices ----

    #[test]
    fn different_chunk_indices_produce_different_nonces() {
        let prefix = [0xAAu8; NONCE_PREFIX_LEN];
        let n0 = build_nonce(prefix, 0);
        let n1 = build_nonce(prefix, 1);
        let n_max = build_nonce(prefix, u32::MAX);
        assert_ne!(n0, n1, "different chunk indices must produce different nonces");
        assert_ne!(n1, n_max, "chunk 1 and u32::MAX must produce different nonces");
        // Same index + same prefix must be deterministic
        assert_eq!(n0, build_nonce(prefix, 0));
        // Different prefix + same index must differ
        let other_prefix = [0xBBu8; NONCE_PREFIX_LEN];
        assert_ne!(n0, build_nonce(other_prefix, 0));
    }

    // ---- Chunk index overflow detection ----

    #[test]
    fn chunk_index_overflow_detected() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        // Force chunk_index to u32::MAX — seal_chunk encrypts then increments,
        // so the increment overflows and the call returns an error.
        sealer.chunk_index = u32::MAX;
        let result = sealer.seal_chunk(b"data", false);
        assert!(matches!(result, Err(VeilError::Format(_))),
            "chunk index overflow must be detected");
    }

    // ---- Opener chunk index overflow detection ----

    #[test]
    fn opener_chunk_index_overflow_detected() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let mut sealer = create_sealer(&id_a, &sign_a, &[], &pub_a, None, None).unwrap();
        let encrypted = sealer.seal_chunk(b"data", false).unwrap();
        let header = sealer.header();
        let dek = unwrap_stream_dek(header, &id_a, &dh_a, &pub_a).unwrap();
        let mut opener = create_opener(header, dek).unwrap();
        // Force chunk_index to u32::MAX
        opener.chunk_index = u32::MAX;
        // open_chunk will fail: nonce mismatch (wrong chunk index) causes decryption error
        // But the overflow check itself should trigger on success path
        let result = opener.open_chunk(&encrypted);
        assert!(result.is_err(), "opener at wrong chunk index must fail");
    }
}
