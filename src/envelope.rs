use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::constants::{self, DOMAIN_DATA, DOMAIN_KEY_WRAP, DOMAIN_SIG_V1};
use crate::crypto::{self, VeilError};

/// A wrapped DEK for a single recipient (ECIES).
#[derive(Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    pub user_id: String,
    pub ephemeral_public: String,
    pub encrypted_dek: String,
}

/// Discriminates between direct (per-recipient) and group envelope access.
#[derive(Clone)]
pub enum EnvelopeAccess {
    /// Per-recipient ECIES-wrapped DEK.
    Direct { recipients: Vec<WrappedKey> },
    /// Group envelope: DEK wrapped with the GEK.
    Group { group_id: String, wrapped_dek: String },
}

/// Encrypted envelope: ciphertext + access control (direct or group).
///
/// **Note on `audit_hash`:** This field is intentionally excluded from the
/// signature payload. The audit hash is set *after* the envelope is sealed
/// and signed (via `anchor_envelope`), so it cannot be part of the original
/// signature. Integrity of the audit binding is verified through
/// `verify_anchor`, which checks that `audit_hash` matches the head of a
/// verified hash chain.
#[derive(Clone)]
pub struct Envelope {
    pub version: u8,
    pub ciphertext: String,
    pub access: EnvelopeAccess,
    pub metadata: Option<serde_json::Value>,
    pub signer_id: Option<String>,
    pub signature: Option<String>,
    pub audit_hash: Option<String>,
}

// ---------- Serde wire format ----------

#[derive(Serialize, Deserialize)]
struct EnvelopeWire {
    version: u8,
    ciphertext: String,
    recipients: Vec<WrappedKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrapped_dek: Option<String>,
}

impl TryFrom<EnvelopeWire> for Envelope {
    type Error = VeilError;

    fn try_from(w: EnvelopeWire) -> Result<Self, Self::Error> {
        if w.version == 0 {
            return Err(VeilError::Format("envelope version must be >= 1".into()));
        }
        if w.version != 1 {
            return Err(VeilError::Format(format!(
                "unsupported envelope version: {}", w.version
            )));
        }
        if w.recipients.len() > constants::MAX_RECIPIENTS {
            return Err(VeilError::Validation(format!(
                "too many recipients: {} (max {})",
                w.recipients.len(),
                constants::MAX_RECIPIENTS
            )));
        }
        {
            let mut seen = HashSet::with_capacity(w.recipients.len());
            for r in &w.recipients {
                if !seen.insert(&r.user_id) {
                    return Err(VeilError::Format(format!(
                        "duplicate recipient '{}' in envelope",
                        r.user_id
                    )));
                }
            }
        }
        constants::validate_metadata(w.metadata.as_ref()).map(drop)?;

        let access = match (w.group_id, w.wrapped_dek) {
            (Some(group_id), Some(wrapped_dek)) => {
                if !w.recipients.is_empty() {
                    return Err(VeilError::Format(
                        "group envelope must not have recipients".into(),
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
            ciphertext: w.ciphertext,
            access,
            metadata: w.metadata,
            signer_id: w.signer_id,
            signature: w.signature,
            audit_hash: w.audit_hash,
        })
    }
}

impl From<Envelope> for EnvelopeWire {
    fn from(e: Envelope) -> Self {
        let (recipients, group_id, wrapped_dek) = match e.access {
            EnvelopeAccess::Direct { recipients } => (recipients, None, None),
            EnvelopeAccess::Group { group_id, wrapped_dek } => {
                (Vec::new(), Some(group_id), Some(wrapped_dek))
            }
        };

        Self {
            version: e.version,
            ciphertext: e.ciphertext,
            recipients,
            metadata: e.metadata,
            signer_id: e.signer_id,
            signature: e.signature,
            audit_hash: e.audit_hash,
            group_id,
            wrapped_dek,
        }
    }
}

impl Serialize for Envelope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = EnvelopeWire::from(self.clone());
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = EnvelopeWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(serde::de::Error::custom)
    }
}

// ---------- Convenience methods on Access ----------

impl EnvelopeAccess {
    pub const fn is_group(&self) -> bool {
        matches!(self, Self::Group { .. })
    }

    pub fn group_id(&self) -> Option<&str> {
        match self {
            Self::Group { group_id, .. } => Some(group_id),
            Self::Direct { .. } => None,
        }
    }

    pub fn recipients(&self) -> &[WrappedKey] {
        match self {
            Self::Direct { recipients } => recipients,
            Self::Group { .. } => &[],
        }
    }

    pub fn group_info(&self) -> Option<(&str, &str)> {
        match self {
            Self::Group { group_id, wrapped_dek } => {
                Some((group_id, wrapped_dek))
            }
            Self::Direct { .. } => None,
        }
    }
}

// ---------- Convenience delegates on Envelope ----------

impl Envelope {
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

// ---------- Wrap / Unwrap ----------

/// Wrap a DEK for a recipient using ECIES.
///
/// 1. Generate ephemeral X25519 keypair
/// 2. DH(ephemeral, recipient) -> shared secret
/// 3. HKDF(shared, info=`"veil-wrap" || eph_pub || recipient_pub`) -> wrapping key
/// 4. AES-256-GCM encrypt the DEK with the wrapping key (AD = `recipient_pub`)
///
/// # Errors
///
/// Returns `VeilError` if key derivation or encryption fails.
pub fn wrap_dek(
    dek: &[u8; 32],
    recipient_id: &str,
    recipient_public: &[u8; 32],
) -> Result<WrappedKey, VeilError> {
    let (eph_secret, eph_public) = crypto::generate_key_pair()?;
    let shared = crypto::dh(&eph_secret, recipient_public)?;

    let mut info = [0u8; 9 + 64];
    info[..9].copy_from_slice(DOMAIN_KEY_WRAP);
    info[9..41].copy_from_slice(&eph_public);
    info[41..73].copy_from_slice(recipient_public);
    let wrapping_key = crypto::hkdf_derive_key(shared.as_ref(), Some(&eph_public), &info)?;

    let encrypted = crypto::aead_encrypt(&wrapping_key, dek, recipient_public)?;

    Ok(WrappedKey {
        user_id: recipient_id.to_string(),
        ephemeral_public: crypto::to_base64(&eph_public),
        encrypted_dek: crypto::to_base64(&encrypted),
    })
}

/// Unwrap a DEK using the recipient's secret key (ECIES reverse).
///
/// # Errors
///
/// Returns `VeilError` if the wrapped key is malformed, the key is wrong,
/// or decryption fails.
pub fn unwrap_dek(
    wrapped: &WrappedKey,
    our_secret: &[u8; 32],
    our_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, VeilError> {
    let eph_pub_bytes: [u8; 32] = crypto::from_base64(&wrapped.ephemeral_public)?
        .try_into()
        .map_err(|_| VeilError::Format("ephemeral public key not 32 bytes".into()))?;

    let shared = crypto::dh(our_secret, &eph_pub_bytes)?;

    let mut info = [0u8; 9 + 64];
    info[..9].copy_from_slice(DOMAIN_KEY_WRAP);
    info[9..41].copy_from_slice(&eph_pub_bytes);
    info[41..73].copy_from_slice(our_public);
    let wrapping_key = crypto::hkdf_derive_key(shared.as_ref(), Some(&eph_pub_bytes), &info)?;

    let encrypted = crypto::from_base64(&wrapped.encrypted_dek)?;
    let dek_bytes = crypto::aead_decrypt(&wrapping_key, &encrypted, our_public)?;

    Ok(Zeroizing::new(<[u8; 32]>::try_from(dek_bytes.as_slice())
        .map_err(|_| VeilError::Format("decrypted DEK not 32 bytes".into()))?))
}

// ---------- Signature ----------

/// Append sorted recipient data to a signature/header payload.
///
/// Format: `num_recipients(4 BE) || for each recipient SORTED by user_id:
///            user_id_len(4 BE) || user_id
///            || ephemeral_public_b64_len(4 BE) || ephemeral_public_b64
///            || encrypted_dek_b64_len(4 BE) || encrypted_dek_b64`
///
/// # Errors
///
/// Returns `VeilError` if any field is too long for a `u32` length prefix.
pub(crate) fn append_recipients_to_payload(
    payload: &mut Vec<u8>,
    recipients: &[WrappedKey],
) -> Result<(), VeilError> {
    let mut sorted: Vec<&WrappedKey> = recipients.iter().collect();
    sorted.sort_by(|a, b| a.user_id.cmp(&b.user_id));

    let num: u32 = sorted.len()
        .try_into()
        .map_err(|_| VeilError::Format("too many recipients for length prefix".into()))?;
    payload.extend_from_slice(&num.to_be_bytes());

    for r in sorted {
        let rid = r.user_id.as_bytes();
        let rid_len: u32 = rid.len()
            .try_into()
            .map_err(|_| VeilError::Format("user_id too long for length prefix".into()))?;
        payload.extend_from_slice(&rid_len.to_be_bytes());
        payload.extend_from_slice(rid);

        let eph = r.ephemeral_public.as_bytes();
        let eph_len: u32 = eph.len()
            .try_into()
            .map_err(|_| VeilError::Format("ephemeral_public too long for length prefix".into()))?;
        payload.extend_from_slice(&eph_len.to_be_bytes());
        payload.extend_from_slice(eph);

        let edek = r.encrypted_dek.as_bytes();
        let edek_len: u32 = edek.len()
            .try_into()
            .map_err(|_| VeilError::Format("encrypted_dek too long for length prefix".into()))?;
        payload.extend_from_slice(&edek_len.to_be_bytes());
        payload.extend_from_slice(edek);
    }

    Ok(())
}

/// Append serialized metadata to a signature/header payload.
///
/// Uses `cached_bytes` if available, otherwise serializes from `metadata`.
pub(crate) fn append_metadata_to_payload(
    payload: &mut Vec<u8>,
    metadata: &Option<serde_json::Value>,
    cached_bytes: Option<&[u8]>,
) -> Result<(), VeilError> {
    if let Some(ref meta) = *metadata {
        payload.push(1);
        let meta_bytes: std::borrow::Cow<'_, [u8]> = if let Some(cached) = cached_bytes {
            std::borrow::Cow::Borrowed(cached)
        } else {
            let serialized = serde_json::to_vec(meta)
                .map_err(|e| VeilError::Encoding(format!("metadata serialize: {e}")))?;
            std::borrow::Cow::Owned(serialized)
        };
        let meta_len: u32 = meta_bytes.len()
            .try_into()
            .map_err(|_| VeilError::Format("metadata too long for length prefix".into()))?;
        payload.extend_from_slice(&meta_len.to_be_bytes());
        payload.extend_from_slice(&meta_bytes);
    } else {
        payload.push(0);
    }
    Ok(())
}

/// Append access data (group or direct recipients) to a signature/header payload.
pub(crate) fn append_access_to_payload(
    payload: &mut Vec<u8>,
    access: &EnvelopeAccess,
) -> Result<(), VeilError> {
    match access {
        EnvelopeAccess::Group { group_id, wrapped_dek } => {
            payload.push(1);
            let gid_bytes = group_id.as_bytes();
            let gid_len: u32 = gid_bytes.len()
                .try_into()
                .map_err(|_| VeilError::Format("group_id too long for length prefix".into()))?;
            payload.extend_from_slice(&gid_len.to_be_bytes());
            payload.extend_from_slice(gid_bytes);
            let wd_bytes = wrapped_dek.as_bytes();
            let wd_len: u32 = wd_bytes.len()
                .try_into()
                .map_err(|_| VeilError::Format("wrapped_dek too long for length prefix".into()))?;
            payload.extend_from_slice(&wd_len.to_be_bytes());
            payload.extend_from_slice(wd_bytes);
        }
        EnvelopeAccess::Direct { recipients } => {
            payload.push(0);
            append_recipients_to_payload(payload, recipients)?;
        }
    }
    Ok(())
}

/// Build the deterministic byte payload that gets signed.
///
/// Format: `"veil-sig-v1" || version(1) || signer_id_len(4 BE) || signer_id
///          || ciphertext_len(4 BE) || ciphertext_b64
///          || has_metadata(1) || [metadata_len(4 BE) || metadata_json]
///          || access_type(1) || access_data`
///
/// Access data for direct envelopes:
///   `num_recipients(4 BE) || for each recipient SORTED by user_id:
///        user_id_len(4 BE) || user_id
///        || ephemeral_public_b64_len(4 BE) || ephemeral_public_b64
///        || encrypted_dek_b64_len(4 BE) || encrypted_dek_b64`
///
/// Access data for group envelopes:
///   `group_id_len(4 BE) || group_id || wrapped_dek_b64_len(4 BE) || wrapped_dek_b64`
///
/// All variable-length fields are length-prefixed to prevent boundary ambiguity.
///
/// # Errors
///
/// Returns `VeilError` if metadata serialization fails.
pub(crate) fn signature_payload(
    envelope: &Envelope,
    cached_metadata: Option<&[u8]>,
) -> Result<Vec<u8>, VeilError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(DOMAIN_SIG_V1);
    payload.push(envelope.version);
    if let Some(ref id) = envelope.signer_id {
        payload.push(1);
        let id_bytes = id.as_bytes();
        let len: u32 = id_bytes.len()
            .try_into()
            .map_err(|_| VeilError::Format("signer_id too long for length prefix".into()))?;
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(id_bytes);
    } else {
        payload.push(0);
    }
    let ct_bytes = envelope.ciphertext.as_bytes();
    let ct_len: u32 = ct_bytes.len()
        .try_into()
        .map_err(|_| VeilError::Format("ciphertext too long for length prefix".into()))?;
    payload.extend_from_slice(&ct_len.to_be_bytes());
    payload.extend_from_slice(ct_bytes);
    append_metadata_to_payload(&mut payload, &envelope.metadata, cached_metadata)?;
    append_access_to_payload(&mut payload, &envelope.access)?;
    Ok(payload)
}

// ---------- Seal / Open ----------

/// Seal data into an envelope, granting access to the sealer and additional recipients.
///
/// `recipient_keys` is a slice of `(user_id, x25519_public)` for other recipients.
/// The sealer is always included as a recipient.
/// `metadata` is optional unencrypted data (sender ID, timestamp, content type, etc.)
/// visible without decryption.
/// The envelope is signed with `sign_secret` (Ed25519).
///
/// # Errors
///
/// Returns `VeilError` if the sealer is in the recipient list, if `recipient_keys`
/// contains duplicate IDs, or if DEK generation, encryption, or key wrapping fails.
pub fn seal(
    plaintext: &[u8],
    our_id: &str,
    our_public: &[u8; 32],
    sign_secret: &[u8; 32],
    recipient_keys: &[(&str, &[u8; 32])],
    metadata: Option<serde_json::Value>,
) -> Result<Envelope, VeilError> {
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

    let mut seen = HashSet::with_capacity(recipient_keys.len());
    for (id, _) in recipient_keys {
        if !seen.insert(*id) {
            return Err(VeilError::Validation(format!("duplicate recipient '{id}'")));
        }
    }

    let dek = crypto::generate_random_key()?;

    let ct = crypto::aead_encrypt(&dek, plaintext, DOMAIN_DATA)?;

    let mut recipients = Vec::with_capacity(1_usize.saturating_add(recipient_keys.len()));
    recipients.push(wrap_dek(&dek, our_id, our_public)?);
    for (id, pub_key) in recipient_keys {
        recipients.push(wrap_dek(&dek, id, pub_key)?);
    }

    let mut envelope = Envelope {
        version: 1,
        ciphertext: crypto::to_base64(&ct),
        access: EnvelopeAccess::Direct { recipients },
        metadata,
        signer_id: Some(our_id.to_string()),
        signature: None,
        audit_hash: None,
    };

    let payload = signature_payload(&envelope, meta_bytes.as_deref())?;
    let sig = crypto::ed25519_sign(sign_secret, &payload);
    envelope.signature = Some(crypto::to_base64(&sig));

    Ok(envelope)
}

/// Verify the Ed25519 signature on an envelope.
///
/// # Errors
///
/// Returns `VeilError` if the envelope is unsigned, the signature is malformed,
/// or verification fails.
pub fn verify(
    envelope: &Envelope,
    signer_public: &[u8; 32],
) -> Result<(), VeilError> {
    let sig_b64 = envelope
        .signature
        .as_ref()
        .ok_or_else(|| VeilError::Encoding("envelope is unsigned".into()))?;

    let sig_bytes: [u8; 64] = crypto::from_base64(sig_b64)?
        .try_into()
        .map_err(|_| VeilError::Crypto("signature is not 64 bytes".into()))?;

    let payload = signature_payload(envelope, None)?;
    crypto::ed25519_verify(signer_public, &payload, &sig_bytes)
}

/// Open an envelope: find our wrapped key, unwrap the DEK, decrypt the data.
///
/// Does not verify the signature — call `verify()` separately if needed.
///
/// # Errors
///
/// Returns `VeilError` if we are not a recipient, or decryption fails.
pub fn open(
    envelope: &Envelope,
    our_id: &str,
    our_secret: &[u8; 32],
    our_public: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, VeilError> {
    if envelope.version != 1 {
        return Err(VeilError::Validation(format!(
            "unsupported envelope version: {}", envelope.version
        )));
    }

    let recipients = match &envelope.access {
        EnvelopeAccess::Direct { recipients } => recipients,
        EnvelopeAccess::Group { .. } => {
            return Err(VeilError::Validation("use group::open for group envelopes".into()));
        }
    };

    let wrapped = recipients
        .iter()
        .find(|w| w.user_id == our_id)
        .ok_or_else(|| VeilError::Encoding("not a recipient of this envelope".into()))?;

    let dek = unwrap_dek(wrapped, our_secret, our_public)?;
    let ct = crypto::from_base64(&envelope.ciphertext)?;
    crypto::aead_decrypt(&dek, &ct, DOMAIN_DATA)
}

/// Add a recipient to an existing envelope.
/// The caller must be an existing recipient (to unwrap the DEK).
/// The envelope is re-signed by the caller.
///
/// # Errors
///
/// Returns `VeilError` if the caller is not a recipient, the new recipient
/// already exists, or key wrapping fails.
pub fn add_recipient(
    envelope: &Envelope,
    our_id: &str,
    our_secret: &[u8; 32],
    our_public: &[u8; 32],
    sign_secret: &[u8; 32],
    new_recipient_id: &str,
    new_recipient_public: &[u8; 32],
) -> Result<Envelope, VeilError> {
    constants::validate_id(new_recipient_id, "new_recipient")?;

    if envelope.version != 1 {
        return Err(VeilError::Format(format!(
            "unsupported envelope version: {}", envelope.version
        )));
    }

    let recipients = match &envelope.access {
        EnvelopeAccess::Direct { recipients } => recipients,
        EnvelopeAccess::Group { .. } => {
            return Err(VeilError::Validation("use add_member for group envelopes".into()));
        }
    };

    if recipients.iter().any(|w| w.user_id == new_recipient_id) {
        return Err(VeilError::Validation(format!("recipient '{new_recipient_id}' already exists")));
    }

    let wrapped = recipients
        .iter()
        .find(|w| w.user_id == our_id)
        .ok_or_else(|| VeilError::Validation("not a recipient of this envelope".into()))?;

    let dek = unwrap_dek(wrapped, our_secret, our_public)?;
    let new_wrapped = wrap_dek(&dek, new_recipient_id, new_recipient_public)?;

    let mut new_recipients = recipients.clone();
    new_recipients.push(new_wrapped);

    let mut new_envelope = Envelope {
        version: envelope.version,
        ciphertext: envelope.ciphertext.clone(),
        access: EnvelopeAccess::Direct { recipients: new_recipients },
        metadata: envelope.metadata.clone(),
        signer_id: Some(our_id.to_string()),
        signature: None,
        audit_hash: envelope.audit_hash.clone(),
    };

    let payload = signature_payload(&new_envelope, None)?;
    let sig = crypto::ed25519_sign(sign_secret, &payload);
    new_envelope.signature = Some(crypto::to_base64(&sig));

    Ok(new_envelope)
}

/// Remove a recipient from an envelope (soft revocation).
/// The envelope is re-signed by the caller.
///
/// The removed user may have already cached the DEK. For hard revocation,
/// re-seal the data with a new DEK.
///
/// # Errors
///
/// Returns `VeilError` if the recipient is not found or if removing them
/// would leave the envelope with no recipients.
pub fn remove_recipient(
    envelope: &Envelope,
    our_id: &str,
    sign_secret: &[u8; 32],
    recipient_id: &str,
) -> Result<Envelope, VeilError> {
    if envelope.version != 1 {
        return Err(VeilError::Format(format!(
            "unsupported envelope version: {}", envelope.version
        )));
    }

    let recipients = match &envelope.access {
        EnvelopeAccess::Direct { recipients } => recipients,
        EnvelopeAccess::Group { .. } => {
            return Err(VeilError::Validation("use remove_member for group envelopes".into()));
        }
    };

    if !recipients.iter().any(|w| w.user_id == our_id) {
        return Err(VeilError::Validation("not a recipient of this envelope".into()));
    }

    if !recipients.iter().any(|w| w.user_id == recipient_id) {
        return Err(VeilError::Validation(format!("recipient '{recipient_id}' not found")));
    }

    if recipients.len() <= 1 {
        return Err(VeilError::Validation("cannot remove the last recipient".into()));
    }

    let new_recipients: Vec<WrappedKey> = recipients
        .iter()
        .filter(|w| w.user_id != recipient_id)
        .cloned()
        .collect();

    let mut new_envelope = Envelope {
        version: envelope.version,
        ciphertext: envelope.ciphertext.clone(),
        access: EnvelopeAccess::Direct { recipients: new_recipients },
        metadata: envelope.metadata.clone(),
        signer_id: Some(our_id.to_string()),
        signature: None,
        audit_hash: envelope.audit_hash.clone(),
    };

    let payload = signature_payload(&new_envelope, None)?;
    let sig = crypto::ed25519_sign(sign_secret, &payload);
    new_envelope.signature = Some(crypto::to_base64(&sig));

    Ok(new_envelope)
}

/// Re-seal an envelope with a fresh DEK (hard revocation).
///
/// Decrypts the data, generates a new DEK, re-encrypts, and wraps for the
/// caller plus the given recipients. Previously cached DEKs become useless.
/// The new envelope is signed by the resealer.
///
/// If `metadata` is `Some`, the new envelope uses it; if `None`, the original
/// envelope's metadata is preserved.
///
/// # Errors
///
/// Returns `VeilError` if the caller is not a recipient of the original envelope,
/// decryption fails, or re-sealing fails.
pub fn reseal(
    envelope: &Envelope,
    our_id: &str,
    our_secret: &[u8; 32],
    our_public: &[u8; 32],
    sign_secret: &[u8; 32],
    recipient_keys: &[(&str, &[u8; 32])],
    metadata: Option<serde_json::Value>,
) -> Result<Envelope, VeilError> {
    let plaintext = open(envelope, our_id, our_secret, our_public)?;
    let meta = metadata.or_else(|| envelope.metadata.clone());
    seal(&plaintext, our_id, our_public, sign_secret, recipient_keys, meta)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::type_complexity, clippy::indexing_slicing, clippy::redundant_clone)]

    use super::*;
    use crate::crypto::{self, VeilError};
    use crate::test_utils::make_user;

    // ---- Wrap / Unwrap ----

    #[test]
    fn wrap_unwrap_roundtrip() {
        let dek = crypto::generate_random_key().unwrap();
        let (id, secret, public, _, _) = make_user();
        let wrapped = wrap_dek(&dek, &id, &public).unwrap();
        let recovered = unwrap_dek(&wrapped, &secret, &public).unwrap();
        assert_eq!(dek, recovered);
    }

    #[test]
    fn unwrap_with_wrong_key_fails() {
        let dek = crypto::generate_random_key().unwrap();
        let (_id_a, _secret_a, public_a, _, _) = make_user();
        let (id_b, secret_b, public_b, _, _) = make_user();
        let wrapped = wrap_dek(&dek, "alice", &public_a).unwrap();
        let result = unwrap_dek(&wrapped, &secret_b, &public_b);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "should fail with wrong key");
        drop(id_b);
    }

    #[test]
    fn wrap_produces_different_ciphertext() {
        let dek = crypto::generate_random_key().unwrap();
        let (_id, _secret, public, _, _) = make_user();
        let w1 = wrap_dek(&dek, "user", &public).unwrap();
        let w2 = wrap_dek(&dek, "user", &public).unwrap();
        assert_ne!(w1.ephemeral_public, w2.ephemeral_public);
        assert_ne!(w1.encrypted_dek, w2.encrypted_dek);
    }

    // ---- Seal / Open ----

    #[test]
    fn seal_open_single_recipient() {
        let (id, secret, public, sign_sec, _) = make_user();
        let env = seal(b"hello world", &id, &public, &sign_sec, &[], None).unwrap();
        assert_eq!(env.version, 1);
        assert_eq!(env.recipients().len(), 1);
        let pt = open(&env, &id, &secret, &public).unwrap();
        assert_eq!(&*pt, b"hello world");
    }

    #[test]
    fn seal_open_multiple_recipients() {
        let (id1, s1, p1, ss1, _) = make_user();
        let (id2, s2, p2, _, _) = make_user();
        let env = seal(
            b"shared secret", &id1, &p1, &ss1, &[(&id2, &p2)], None,
        ).unwrap();
        assert_eq!(env.recipients().len(), 2);
        let pt1 = open(&env, &id1, &s1, &p1).unwrap();
        let pt2 = open(&env, &id2, &s2, &p2).unwrap();
        assert_eq!(&*pt1, b"shared secret");
        assert_eq!(&*pt2, b"shared secret");
    }

    #[test]
    fn open_by_non_recipient_fails() {
        let (id1, _s1, p1, ss1, _) = make_user();
        let (id2, s2, p2, _, _) = make_user();
        let env = seal(b"private", &id1, &p1, &ss1, &[], None).unwrap();
        let result = open(&env, &id2, &s2, &p2);
        assert!(matches!(result, Err(VeilError::Encoding(_))), "non-recipient must not open envelope");
    }

    #[test]
    fn seal_empty_plaintext() {
        let (id, secret, public, sign_sec, _) = make_user();
        let env = seal(b"", &id, &public, &sign_sec, &[], None).unwrap();
        let pt = open(&env, &id, &secret, &public).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn seal_large_plaintext() {
        let (id, secret, public, sign_sec, _) = make_user();
        let data = vec![0xABu8; 100_000];
        let env = seal(&data, &id, &public, &sign_sec, &[], None).unwrap();
        let pt = open(&env, &id, &secret, &public).unwrap();
        assert_eq!(&*pt, &*data);
    }

    // ---- Add / Remove Recipient ----

    #[test]
    fn add_recipient_then_open() {
        let (id1, s1, p1, ss1, _) = make_user();
        let (id2, s2, p2, _, _) = make_user();
        let env = seal(b"original", &id1, &p1, &ss1, &[], None).unwrap();
        assert_eq!(env.recipients().len(), 1);
        let env2 = add_recipient(&env, &id1, &s1, &p1, &ss1, &id2, &p2).unwrap();
        assert_eq!(env2.recipients().len(), 2);
        let pt = open(&env2, &id2, &s2, &p2).unwrap();
        assert_eq!(&*pt, b"original");
    }

    #[test]
    fn add_recipient_preserves_existing() {
        let (id1, s1, p1, ss1, _) = make_user();
        let (id2, _s2, p2, _, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[], None).unwrap();
        let env2 = add_recipient(&env, &id1, &s1, &p1, &ss1, &id2, &p2).unwrap();
        let pt = open(&env2, &id1, &s1, &p1).unwrap();
        assert_eq!(&*pt, b"data");
    }

    #[test]
    fn add_duplicate_recipient_errors() {
        let (id1, s1, p1, ss1, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[], None).unwrap();
        let result = add_recipient(&env, &id1, &s1, &p1, &ss1, &id1, &p1);
        assert!(matches!(result, Err(VeilError::Validation(_))), "duplicate recipient must be rejected");
    }

    #[test]
    fn remove_recipient_then_open_fails() {
        let (id1, _s1, p1, ss1, _) = make_user();
        let (id2, s2, p2, _, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[(&id2, &p2)], None).unwrap();
        let env2 = remove_recipient(&env, &id1, &ss1, &id2).unwrap();
        let result = open(&env2, &id2, &s2, &p2);
        assert!(matches!(result, Err(VeilError::Encoding(_))), "removed recipient must not open envelope");
    }

    #[test]
    fn remove_recipient_preserves_others() {
        let (id1, s1, p1, ss1, _) = make_user();
        let (id2, _s2, p2, _, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[(&id2, &p2)], None).unwrap();
        let env2 = remove_recipient(&env, &id1, &ss1, &id2).unwrap();
        let pt = open(&env2, &id1, &s1, &p1).unwrap();
        assert_eq!(&*pt, b"data");
    }

    #[test]
    fn remove_nonexistent_recipient_errors() {
        let (id1, _s1, p1, ss1, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[], None).unwrap();
        let result = remove_recipient(&env, &id1, &ss1, "nobody");
        assert!(matches!(result, Err(VeilError::Validation(_))), "nonexistent recipient must be rejected");
    }

    // ---- Serialization ----

    #[test]
    fn envelope_json_roundtrip() {
        let (id, secret, public, sign_sec, _) = make_user();
        let env = seal(b"json test", &id, &public, &sign_sec, &[], None).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let env2: Envelope = serde_json::from_str(&json).unwrap();
        let pt = open(&env2, &id, &secret, &public).unwrap();
        assert_eq!(&*pt, b"json test");
    }

    // ---- Security ----

    #[test]
    fn different_seals_produce_different_deks() {
        let (id, _secret, public, sign_sec, _) = make_user();
        let env1 = seal(b"same data", &id, &public, &sign_sec, &[], None).unwrap();
        let env2 = seal(b"same data", &id, &public, &sign_sec, &[], None).unwrap();
        assert_ne!(env1.ciphertext, env2.ciphertext);
    }

    #[test]
    fn seal_rejects_duplicate_recipients() {
        let (id1, _s1, p1, ss1, _) = make_user();
        let (id2, _s2, p2, _, _) = make_user();
        let result = seal(b"data", &id1, &p1, &ss1, &[(&id2, &p2), (&id2, &p2)], None);
        assert!(matches!(result, Err(VeilError::Validation(_))), "duplicate recipient IDs must be rejected");
    }

    #[test]
    fn remove_last_recipient_errors() {
        let (id1, _s1, p1, ss1, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[], None).unwrap();
        let result = remove_recipient(&env, &id1, &ss1, &id1);
        assert!(matches!(result, Err(VeilError::Validation(_))), "removing the last recipient must fail");
    }

    // ---- Metadata ----

    #[test]
    fn seal_with_metadata() {
        let (id, secret, public, sign_sec, _) = make_user();
        let meta = serde_json::json!({"sender": "alice", "type": "message"});
        let env = seal(b"hello", &id, &public, &sign_sec, &[], Some(meta.clone())).unwrap();
        assert_eq!(env.metadata, Some(meta));
        let pt = open(&env, &id, &secret, &public).unwrap();
        assert_eq!(&*pt, b"hello");
    }

    #[test]
    fn seal_without_metadata_omits_field() {
        let (id, _secret, public, sign_sec, _) = make_user();
        let env = seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
        assert!(env.metadata.is_none());
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("\"metadata\""), "null metadata must be omitted from JSON");
    }

    #[test]
    fn cross_recipient_dek_substitution_fails() {
        let (id1, s1, p1, ss1, _) = make_user();
        let (id2, s2, p2, _, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[(&id2, &p2)], None).unwrap();
        let mut tampered = env.clone();
        if let EnvelopeAccess::Direct { ref mut recipients } = tampered.access {
            let dek_0 = recipients[0].encrypted_dek.clone();
            recipients[0].encrypted_dek = recipients[1].encrypted_dek.clone();
            recipients[1].encrypted_dek = dek_0;
        }
        let result1 = open(&tampered, &id1, &s1, &p1);
        assert!(matches!(result1, Err(VeilError::Crypto(_))), "cross-swapped DEK must fail for recipient 1");
        let result2 = open(&tampered, &id2, &s2, &p2);
        assert!(matches!(result2, Err(VeilError::Crypto(_))), "cross-swapped DEK must fail for recipient 2");
    }

    #[test]
    fn metadata_preserved_by_add_recipient() {
        let (id1, s1, p1, ss1, _) = make_user();
        let (id2, _s2, p2, _, _) = make_user();
        let meta = serde_json::json!({"sender": "alice"});
        let env = seal(b"data", &id1, &p1, &ss1, &[], Some(meta.clone())).unwrap();
        let env2 = add_recipient(&env, &id1, &s1, &p1, &ss1, &id2, &p2).unwrap();
        assert_eq!(env2.metadata, Some(meta));
    }

    #[test]
    fn metadata_preserved_by_remove_recipient() {
        let (id1, _s1, p1, ss1, _) = make_user();
        let (id2, _s2, p2, _, _) = make_user();
        let meta = serde_json::json!({"sender": "alice"});
        let env = seal(b"data", &id1, &p1, &ss1, &[(&id2, &p2)], Some(meta.clone())).unwrap();
        let env2 = remove_recipient(&env, &id1, &ss1, &id2).unwrap();
        assert_eq!(env2.metadata, Some(meta));
    }

    #[test]
    fn version_mismatch_rejected() {
        let (id, secret, public, sign_sec, _) = make_user();
        let mut env = seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
        env.version = 2;
        let result = open(&env, &id, &secret, &public);
        assert!(matches!(result, Err(VeilError::Validation(_))), "version != 1 must be rejected on open");
        let (id2, _s2, p2, _, _) = make_user();
        let result = add_recipient(&env, &id, &secret, &public, &sign_sec, &id2, &p2);
        assert!(matches!(result, Err(VeilError::Format(_))), "version != 1 must be rejected on add_recipient");
    }

    // ---- Reseal (hard revocation) ----

    #[test]
    fn reseal_produces_new_dek() {
        let (id1, s1, p1, ss1, _) = make_user();
        let (id2, _s2, p2, _, _) = make_user();
        let env = seal(b"secret", &id1, &p1, &ss1, &[(&id2, &p2)], None).unwrap();
        let resealed = reseal(&env, &id1, &s1, &p1, &ss1, &[], None).unwrap();
        assert_ne!(env.ciphertext, resealed.ciphertext, "reseal must use a new DEK");
    }

    #[test]
    fn reseal_excludes_removed_recipient() {
        let (id1, s1, p1, ss1, _) = make_user();
        let (id2, s2, p2, _, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[(&id2, &p2)], None).unwrap();
        let resealed = reseal(&env, &id1, &s1, &p1, &ss1, &[], None).unwrap();
        assert_eq!(resealed.recipients().len(), 1);
        let result = open(&resealed, &id2, &s2, &p2);
        assert!(matches!(result, Err(VeilError::Encoding(_))), "removed recipient must not open resealed envelope");
    }

    #[test]
    fn reseal_preserves_plaintext() {
        let (id1, s1, p1, ss1, _) = make_user();
        let env = seal(b"keep this", &id1, &p1, &ss1, &[], None).unwrap();
        let resealed = reseal(&env, &id1, &s1, &p1, &ss1, &[], None).unwrap();
        let pt = open(&resealed, &id1, &s1, &p1).unwrap();
        assert_eq!(&*pt, b"keep this");
    }

    #[test]
    fn reseal_preserves_metadata_by_default() {
        let (id1, s1, p1, ss1, _) = make_user();
        let meta = serde_json::json!({"sender": "alice"});
        let env = seal(b"data", &id1, &p1, &ss1, &[], Some(meta.clone())).unwrap();
        let resealed = reseal(&env, &id1, &s1, &p1, &ss1, &[], None).unwrap();
        assert_eq!(resealed.metadata, Some(meta));
    }

    #[test]
    fn reseal_replaces_metadata_when_provided() {
        let (id1, s1, p1, ss1, _) = make_user();
        let old_meta = serde_json::json!({"v": 1});
        let new_meta = serde_json::json!({"v": 2});
        let env = seal(b"data", &id1, &p1, &ss1, &[], Some(old_meta)).unwrap();
        let resealed = reseal(&env, &id1, &s1, &p1, &ss1, &[], Some(new_meta.clone())).unwrap();
        assert_eq!(resealed.metadata, Some(new_meta));
    }

    #[test]
    fn reseal_by_non_recipient_fails() {
        let (id1, _s1, p1, ss1, _) = make_user();
        let (id2, s2, p2, ss2, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[], None).unwrap();
        let result = reseal(&env, &id2, &s2, &p2, &ss2, &[], None);
        assert!(matches!(result, Err(VeilError::Encoding(_))), "non-recipient must not reseal envelope");
    }

    // ---- Signatures ----

    #[test]
    fn seal_produces_signature() {
        let (id, _secret, public, sign_sec, _) = make_user();
        let env = seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
        assert!(env.signature.is_some(), "sealed envelope must have a signature");
        assert_eq!(env.signer_id.as_deref(), Some(id.as_str()));
    }

    #[test]
    fn verify_valid_signature() {
        let (id, _secret, public, sign_sec, sign_pub) = make_user();
        let env = seal(b"signed data", &id, &public, &sign_sec, &[], None).unwrap();
        assert!(verify(&env, &sign_pub).is_ok());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (id, _secret, public, sign_sec, _) = make_user();
        let (_, _, _, _, other_sign_pub) = make_user();
        let env = seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
        let result = verify(&env, &other_sign_pub);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "wrong signer key must fail verification");
    }

    #[test]
    fn verify_tampered_ciphertext_fails() {
        let (id, _secret, public, sign_sec, sign_pub) = make_user();
        let mut env = seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
        env.ciphertext = crypto::to_base64(b"tampered");
        let result = verify(&env, &sign_pub);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "tampered ciphertext must fail verification");
    }

    #[test]
    fn verify_tampered_metadata_fails() {
        let (id, _secret, public, sign_sec, sign_pub) = make_user();
        let meta = serde_json::json!({"sender": "alice"});
        let mut env = seal(b"data", &id, &public, &sign_sec, &[], Some(meta)).unwrap();
        env.metadata = Some(serde_json::json!({"sender": "mallory"}));
        let result = verify(&env, &sign_pub);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "tampered metadata must fail verification");
    }

    #[test]
    fn add_recipient_re_signs_envelope() {
        let (id1, s1, p1, ss1, sp1) = make_user();
        let (id2, _s2, p2, _, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[], None).unwrap();
        let env2 = add_recipient(&env, &id1, &s1, &p1, &ss1, &id2, &p2).unwrap();
        assert_eq!(env2.signer_id.as_deref(), Some(id1.as_str()));
        assert!(verify(&env2, &sp1).is_ok());
        assert_ne!(env.signature, env2.signature);
    }

    #[test]
    fn remove_recipient_re_signs_envelope() {
        let (id1, _s1, p1, ss1, sp1) = make_user();
        let (id2, _s2, p2, _, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[(&id2, &p2)], None).unwrap();
        let env2 = remove_recipient(&env, &id1, &ss1, &id2).unwrap();
        assert_eq!(env2.signer_id.as_deref(), Some(id1.as_str()));
        assert!(verify(&env2, &sp1).is_ok());
        assert_ne!(env.signature, env2.signature);
    }

    #[test]
    fn signature_detects_recipient_stripping() {
        let (id1, _s1, p1, ss1, sp1) = make_user();
        let (id2, _s2, p2, _, _) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[(&id2, &p2)], None).unwrap();
        assert_eq!(env.recipients().len(), 2);
        let mut tampered = env.clone();
        if let EnvelopeAccess::Direct { ref mut recipients } = tampered.access {
            recipients.retain(|w| w.user_id == id1);
        }
        let result = verify(&tampered, &sp1);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "recipient stripping must invalidate the signature");
    }

    #[test]
    fn reseal_re_signs_with_resealer() {
        let (id1, _s1, p1, ss1, sp1) = make_user();
        let (id2, s2, p2, ss2, sp2) = make_user();
        let env = seal(b"data", &id1, &p1, &ss1, &[(&id2, &p2)], None).unwrap();
        assert_eq!(env.signer_id.as_deref(), Some(id1.as_str()));
        assert!(verify(&env, &sp1).is_ok());
        let resealed = reseal(&env, &id2, &s2, &p2, &ss2, &[], None).unwrap();
        assert_eq!(resealed.signer_id.as_deref(), Some(id2.as_str()));
        assert!(verify(&resealed, &sp2).is_ok());
        assert!(matches!(verify(&resealed, &sp1), Err(VeilError::Crypto(_))), "wrong signer key must fail");
    }

    #[test]
    fn unsigned_envelope_still_opens() {
        let (id, secret, public, sign_sec, _) = make_user();
        let env = seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
        let mut unsigned = env;
        unsigned.signature = None;
        unsigned.signer_id = None;
        let pt = open(&unsigned, &id, &secret, &public).unwrap();
        assert_eq!(&*pt, b"data");
        let (_, _, _, _, any_pub) = make_user();
        assert!(matches!(verify(&unsigned, &any_pub), Err(VeilError::Encoding(_))), "unsigned envelope must fail verification");
    }

    #[test]
    fn signature_json_roundtrip() {
        let (id, _secret, public, sign_sec, sign_pub) = make_user();
        let env = seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let env2: Envelope = serde_json::from_str(&json).unwrap();
        assert!(verify(&env2, &sign_pub).is_ok());
    }

    // ---- Version edge cases ----

    #[test]
    fn version_zero_rejected() {
        let (id, secret, public, sign_sec, _) = make_user();
        let mut env = seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
        env.version = 0;
        let result = open(&env, &id, &secret, &public);
        assert!(result.is_err(), "version 0 must be rejected");
    }

    #[test]
    fn version_255_rejected() {
        let (id, secret, public, sign_sec, _) = make_user();
        let mut env = seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
        env.version = 255;
        let result = open(&env, &id, &secret, &public);
        assert!(result.is_err(), "version 255 must be rejected");
    }

    // ---- Unicode user IDs ----

    #[test]
    fn unicode_user_id_roundtrip() {
        let (_id, secret, public, sign_sec, sign_pub) = make_user();
        let unicode_id = "用户-αβγ-🔐";
        let env = seal(b"hello", unicode_id, &public, &sign_sec, &[], None).unwrap();
        assert!(verify(&env, &sign_pub).is_ok());
        let pt = open(&env, unicode_id, &secret, &public).unwrap();
        assert_eq!(&*pt, b"hello");
    }

    // ---- Large metadata ----

    #[test]
    fn large_metadata_roundtrip() {
        let (id, secret, public, sign_sec, sign_pub) = make_user();
        let large_value = "x".repeat(100_000);
        let meta = serde_json::json!({ "big": large_value });
        let env = seal(b"data", &id, &public, &sign_sec, &[], Some(meta.clone())).unwrap();
        assert!(verify(&env, &sign_pub).is_ok());
        let pt = open(&env, &id, &secret, &public).unwrap();
        assert_eq!(&*pt, b"data");
        assert_eq!(env.metadata.unwrap()["big"], large_value);
    }

    // ---- Metadata with null bytes ----

    #[test]
    fn metadata_with_special_chars() {
        let (id, secret, public, sign_sec, _) = make_user();
        let meta = serde_json::json!({ "key": "value\u{0000}with\nnewlines\ttabs" });
        let env = seal(b"data", &id, &public, &sign_sec, &[], Some(meta)).unwrap();
        let pt = open(&env, &id, &secret, &public).unwrap();
        assert_eq!(&*pt, b"data");
    }

    // ---- Tampered signer_id invalidates signature ----

    #[test]
    fn tampered_signer_id_fails_verification() {
        let (id, _, public, sign_sec, sign_pub) = make_user();
        let mut env = seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
        env.signer_id = Some("attacker".to_string());
        assert!(matches!(verify(&env, &sign_pub), Err(VeilError::Crypto(_))),
            "tampered signer_id must invalidate signature");
    }

    // ---- Recipient stripping on add_recipient ----

    #[test]
    fn add_recipient_to_stripped_envelope_fails() {
        let (id_a, dh_a, pub_a, sign_a, _) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _) = make_user();
        let (id_c, _dh_c, _pub_c, _sign_c, _) = make_user();

        let recipients: Vec<(&str, &[u8; 32])> = vec![(&id_b, &pub_b)];
        let env = seal(b"data", &id_a, &pub_a, &sign_a, &recipients, None).unwrap();

        // Try to add_recipient as a non-recipient (id_c)
        let result = add_recipient(
            &env, &id_c, &dh_a, &pub_a, &sign_a, // wrong user for the DH key
            "new_user", &[42u8; 32],
        );
        assert!(result.is_err(), "non-recipient must not be able to add recipients");
    }

    // ---- ID length validation ----

    #[test]
    fn empty_sealer_id_rejected() {
        let (_, _, public, sign_sec, _) = make_user();
        let result = seal(b"data", "", &public, &sign_sec, &[], None);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "empty sealer ID must be rejected");
    }

    #[test]
    fn oversized_user_id_rejected() {
        let (_, _, public, sign_sec, _) = make_user();
        let huge_id = "x".repeat(1024);
        let result = seal(b"data", &huge_id, &public, &sign_sec, &[], None);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "oversized user_id must be rejected");
    }

    #[test]
    fn oversized_recipient_id_rejected() {
        let (id, _, public, sign_sec, _) = make_user();
        let huge_id = "r".repeat(1024);
        let result = seal(b"data", &id, &public, &sign_sec, &[(&huge_id, &[42u8; 32])], None);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "oversized recipient ID must be rejected");
    }

    // ---- Metadata size validation ----

    #[test]
    fn oversized_metadata_rejected() {
        let (id, _, public, sign_sec, _) = make_user();
        // Create metadata exceeding MAX_METADATA_LEN (256 KiB)
        let big_str = "x".repeat(300_000);
        let meta = serde_json::json!({ "data": big_str });
        let result = seal(b"data", &id, &public, &sign_sec, &[], Some(meta));
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "oversized metadata must be rejected");
    }

    // ---- Deserialization validation ----

    #[test]
    fn deserialized_envelope_version_zero_rejected() {
        let json = r#"{"version":0,"ciphertext":"AAAA","recipients":[]}"#;
        let result: Result<Envelope, _> = serde_json::from_str::<super::EnvelopeWire>(json)
            .map_err(|e| VeilError::Encoding(format!("{e}")))
            .and_then(Envelope::try_from);
        assert!(matches!(result, Err(VeilError::Format(_))),
            "deserialized envelope with version 0 must be rejected");
    }

    // ---- Control character rejection ----

    #[test]
    fn null_byte_in_user_id_rejected() {
        let (_, _, public, sign_sec, _) = make_user();
        let result = seal(b"data", "alice\x00evil", &public, &sign_sec, &[], None);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "null byte in user_id must be rejected");
    }

    #[test]
    fn tab_in_recipient_id_rejected() {
        let (id, _, public, sign_sec, _) = make_user();
        let result = seal(b"data", &id, &public, &sign_sec, &[("bob\ttab", &[42u8; 32])], None);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "tab in recipient ID must be rejected");
    }

    // ---- add_recipient validates new recipient ID ----

    #[test]
    fn add_recipient_validates_new_id() {
        let (id_a, dh_a, pub_a, sign_a, _) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _) = make_user();
        let env = seal(b"data", &id_a, &pub_a, &sign_a, &[(&id_b, &pub_b)], None).unwrap();
        let result = add_recipient(
            &env, &id_a, &dh_a, &pub_a, &sign_a,
            "new\x00user", &[42u8; 32],
        );
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "add_recipient must validate new recipient ID");
    }

    // ---- Deserialized duplicate recipients rejected ----

    #[test]
    fn deserialized_duplicate_recipients_rejected() {
        let json = r#"{"version":1,"ciphertext":"AAAA","recipients":[
            {"user_id":"alice","ephemeral_public":"AAAA","encrypted_dek":"BBBB"},
            {"user_id":"alice","ephemeral_public":"CCCC","encrypted_dek":"DDDD"}
        ]}"#;
        let result: Result<Envelope, _> = serde_json::from_str(json);
        assert!(result.is_err(),
            "deserialized envelope with duplicate recipients must be rejected");
    }

    // ---- Deserialized envelope version 2 rejected ----

    #[test]
    fn deserialized_envelope_version_two_rejected() {
        let json = r#"{"version":2,"ciphertext":"AAAA","recipients":[]}"#;
        let result: Result<Envelope, _> = serde_json::from_str::<super::EnvelopeWire>(json)
            .map_err(|e| VeilError::Encoding(format!("{e}")))
            .and_then(Envelope::try_from);
        assert!(matches!(result, Err(VeilError::Format(_))),
            "deserialized envelope with version 2 must be rejected");
    }

    // ---- Inconsistent group fields ----

    #[test]
    fn deserialized_group_id_without_wrapped_dek_rejected() {
        let json = r#"{"version":1,"ciphertext":"AAAA","recipients":[],"group_id":"team"}"#;
        let result: Result<Envelope, _> = serde_json::from_str(json);
        assert!(result.is_err(),
            "group_id without wrapped_dek must be rejected");
    }

    #[test]
    fn deserialized_wrapped_dek_without_group_id_rejected() {
        let json = r#"{"version":1,"ciphertext":"AAAA","recipients":[],"wrapped_dek":"AAAA"}"#;
        let result: Result<Envelope, _> = serde_json::from_str(json);
        assert!(result.is_err(),
            "wrapped_dek without group_id must be rejected");
    }

    #[test]
    fn deserialized_group_envelope_with_recipients_rejected() {
        let json = r#"{"version":1,"ciphertext":"AAAA","recipients":[
            {"user_id":"alice","ephemeral_public":"AAAA","encrypted_dek":"BBBB"}
        ],"group_id":"team","wrapped_dek":"CCCC"}"#;
        let result: Result<Envelope, _> = serde_json::from_str(json);
        assert!(result.is_err(),
            "group envelope with recipients must be rejected");
    }

    // ---- Malformed WrappedKey base64 ----

    #[test]
    fn unwrap_dek_malformed_ephemeral_public_fails() {
        let (_, secret, public, _, _) = make_user();
        let wrapped = WrappedKey {
            user_id: "alice".to_string(),
            ephemeral_public: "not-valid-base64!!!".to_string(),
            encrypted_dek: crypto::to_base64(&[0u8; 60]),
        };
        let result = unwrap_dek(&wrapped, &secret, &public);
        assert!(matches!(result, Err(VeilError::Encoding(_))),
            "malformed ephemeral_public base64 must be rejected");
    }

    #[test]
    fn unwrap_dek_wrong_size_ephemeral_public_fails() {
        let (_, secret, public, _, _) = make_user();
        let wrapped = WrappedKey {
            user_id: "alice".to_string(),
            ephemeral_public: crypto::to_base64(&[0xABu8; 16]), // 16 bytes, not 32
            encrypted_dek: crypto::to_base64(&[0u8; 60]),
        };
        let result = unwrap_dek(&wrapped, &secret, &public);
        assert!(matches!(result, Err(VeilError::Format(_))),
            "ephemeral_public that is not 32 bytes must be rejected");
    }

    #[test]
    fn unwrap_dek_malformed_encrypted_dek_fails() {
        let dek = crypto::generate_random_key().unwrap();
        let (_, secret, public, _, _) = make_user();
        let mut wrapped = wrap_dek(&dek, "alice", &public).unwrap();
        wrapped.encrypted_dek = "not-valid-base64!!!".to_string();
        let result = unwrap_dek(&wrapped, &secret, &public);
        assert!(matches!(result, Err(VeilError::Encoding(_))),
            "malformed encrypted_dek base64 must be rejected");
    }

    // ---- Seal rejects sealer in recipient list ----

    #[test]
    fn seal_rejects_self_in_recipients() {
        let (id, _, public, sign_sec, _) = make_user();
        let result = seal(b"data", &id, &public, &sign_sec, &[(&id, &public)], None);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "sealer in recipient list must be rejected");
    }
}
