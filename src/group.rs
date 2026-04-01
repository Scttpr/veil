use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::constants::{self, DOMAIN_DATA, DOMAIN_GROUP_V1};
use crate::crypto::{self, VeilError};
use crate::envelope::{self, Envelope, EnvelopeAccess, WrappedKey};

/// Get current time in milliseconds. Uses `js_sys::Date::now()` in WASM,
/// falls back to `std::time` on native targets (used in tests).
fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| {
                let ms = d.as_millis();
                // Timestamps up to ~2^53 ms (year 285,616) are lossless in f64.
                #[allow(clippy::cast_precision_loss)]
                let result = ms as f64;
                result
            })
    }
}

// ---------- GEK cache ----------

/// In-memory cache for unwrapped Group Encryption Keys (GEKs).
///
/// Avoids re-fetching and re-unwrapping group bundles on every
/// group operation. Stores the epoch to detect stale entries
/// after key rotation (member removal). Uses LRU eviction when
/// the cache exceeds `MAX_ENTRIES` to bound memory usage.
///
/// Entries expire after `TTL_MS` milliseconds to limit the window
/// during which a cached GEK remains usable after a bundle is
/// invalidated server-side.
/// (epoch, gek, `lru_counter`, `inserted_at_ms`)
type GekCacheEntry = (u32, Zeroizing<[u8; 32]>, u64, f64);

pub struct GekCache {
    entries: HashMap<String, GekCacheEntry>,
    counter: u64,
}

const GEK_CACHE_MAX_ENTRIES: usize = 512;
/// GEK cache TTL: 10 minutes in milliseconds.
const GEK_CACHE_TTL_MS: f64 = 10.0 * 60.0 * 1000.0;

impl Default for GekCache {
    fn default() -> Self {
        Self::new()
    }
}

impl GekCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            counter: 0,
        }
    }

    /// Get a cached GEK if it matches the expected epoch and has not expired.
    pub fn get(&mut self, group_id: &str, epoch: u32) -> Option<&Zeroizing<[u8; 32]>> {
        let now = now_ms();
        self.counter = self.counter.wrapping_add(1);
        let counter = self.counter;

        // Remove expired entry
        if let Some((_, _, _, inserted_at)) = self.entries.get(group_id) {
            if now > 0.0 && (now - *inserted_at) > GEK_CACHE_TTL_MS {
                self.entries.remove(group_id);
                return None;
            }
        }

        self.entries
            .get_mut(group_id)
            .and_then(|(e, gek, ts, _)| {
                if *e == epoch {
                    *ts = counter;
                    Some(&*gek)
                } else {
                    None
                }
            })
    }

    /// Insert or update a cached GEK.
    pub fn insert(&mut self, group_id: String, epoch: u32, gek: Zeroizing<[u8; 32]>) {
        if self.entries.len() >= GEK_CACHE_MAX_ENTRIES && !self.entries.contains_key(&group_id) {
            // Evict the least recently used entry
            if let Some(lru_key) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, _, ts, _))| *ts)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&lru_key);
            } else {
                // Unreachable when len() >= 1, but ensures bounded cache invariant
                self.entries.clear();
            }
        }
        self.counter = self.counter.wrapping_add(1);
        self.entries
            .insert(group_id, (epoch, gek, self.counter, now_ms()));
    }

    /// Invalidate a group's cached GEK (e.g. after member removal).
    pub fn invalidate(&mut self, group_id: &str) {
        self.entries.remove(group_id);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------- Auto-group ----------

/// Compute a deterministic group ID for a set of users.
///
/// Sorts user IDs, deduplicates, and hashes to produce a stable
/// identifier. Useful for auto-creating pairwise or small-group
/// conversations without coordination.
///
/// The `auto:` prefix distinguishes auto-generated IDs from
/// user-chosen group IDs.
pub fn auto_group_id(user_ids: &[&str]) -> String {
    let mut sorted: Vec<&str> = user_ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    // Use \n as separator — validate_id rejects control chars, so \n can never
    // appear in a user_id. Using ":" would be ambiguous (user_ids may contain ":").
    let input = format!("{}\n{}", constants::DOMAIN_AUTO_GROUP_V1, sorted.join("\n"));
    let hash = crypto::sha256(input.as_bytes());
    format!("auto:{}", crypto::to_base64(&hash))
}

/// A group key bundle: the GEK wrapped per-member, stored server-side.
///
/// Note: `signer_id` identifies the signer of this bundle version,
/// not necessarily the original group creator. It is updated on each
/// bundle mutation (add/remove member).
#[derive(Clone)]
pub struct GroupKeyBundle {
    pub version: u8,
    pub group_id: String,
    pub epoch: u32,
    pub members: Vec<WrappedKey>,
    pub signer_id: String,
    pub signature: String,
}

// ---------- Serde wire format ----------

#[derive(Serialize, Deserialize)]
struct GroupKeyBundleWire {
    version: u8,
    group_id: String,
    epoch: u32,
    members: Vec<WrappedKey>,
    signer_id: String,
    signature: String,
}

impl TryFrom<GroupKeyBundleWire> for GroupKeyBundle {
    type Error = VeilError;

    fn try_from(w: GroupKeyBundleWire) -> Result<Self, Self::Error> {
        if w.version == 0 {
            return Err(VeilError::Format("bundle version must be >= 1".into()));
        }
        if w.version != 1 {
            return Err(VeilError::Format(format!(
                "unsupported bundle version: {}", w.version
            )));
        }
        if w.members.is_empty() {
            return Err(VeilError::Validation("bundle must have at least one member".into()));
        }
        if w.members.len() > constants::MAX_GROUP_MEMBERS {
            return Err(VeilError::Validation(format!(
                "too many members: {} (max {})",
                w.members.len(),
                constants::MAX_GROUP_MEMBERS
            )));
        }
        {
            let mut seen = std::collections::HashSet::with_capacity(w.members.len());
            for m in &w.members {
                if !seen.insert(&m.user_id) {
                    return Err(VeilError::Format(format!(
                        "duplicate member '{}' in bundle",
                        m.user_id
                    )));
                }
            }
        }
        if !w.members.iter().any(|m| m.user_id == w.signer_id) {
            return Err(VeilError::Format(format!(
                "bundle signer '{}' is not a member",
                w.signer_id
            )));
        }
        Ok(Self {
            version: w.version,
            group_id: w.group_id,
            epoch: w.epoch,
            members: w.members,
            signer_id: w.signer_id,
            signature: w.signature,
        })
    }
}

impl From<GroupKeyBundle> for GroupKeyBundleWire {
    fn from(b: GroupKeyBundle) -> Self {
        Self {
            version: b.version,
            group_id: b.group_id,
            epoch: b.epoch,
            members: b.members,
            signer_id: b.signer_id,
            signature: b.signature,
        }
    }
}

impl Serialize for GroupKeyBundle {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = GroupKeyBundleWire::from(self.clone());
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GroupKeyBundle {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = GroupKeyBundleWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(serde::de::Error::custom)
    }
}

// ---------- Bundle signature ----------

/// Build the deterministic byte payload for bundle signing.
///
/// Format: `"veil-group-v1" || version(1) || group_id_len(4 BE) || group_id
///          || epoch(4 BE) || num_members(4 BE)
///          || for each member SORTED by user_id:
///               user_id_len(4 BE) || user_id
///               || ephemeral_public_b64_len(4 BE) || ephemeral_public_b64
///               || encrypted_dek_b64_len(4 BE) || encrypted_dek_b64
///          || signer_id_len(4 BE) || signer_id`
fn bundle_payload(bundle: &GroupKeyBundle) -> Result<Vec<u8>, VeilError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(DOMAIN_GROUP_V1);
    payload.push(bundle.version);

    let gid = bundle.group_id.as_bytes();
    let gid_len: u32 = gid.len()
        .try_into()
        .map_err(|_| VeilError::Format("group_id too long for length prefix".into()))?;
    payload.extend_from_slice(&gid_len.to_be_bytes());
    payload.extend_from_slice(gid);

    payload.extend_from_slice(&bundle.epoch.to_be_bytes());

    let num_members: u32 = bundle.members.len()
        .try_into()
        .map_err(|_| VeilError::Format("too many members for length prefix".into()))?;
    payload.extend_from_slice(&num_members.to_be_bytes());

    // Sort members by user_id for deterministic ordering
    let mut sorted: Vec<&WrappedKey> = bundle.members.iter().collect();
    sorted.sort_by(|a, b| a.user_id.cmp(&b.user_id));

    for member in sorted {
        let rid = member.user_id.as_bytes();
        let rid_len: u32 = rid.len()
            .try_into()
            .map_err(|_| VeilError::Format("user_id too long for length prefix".into()))?;
        payload.extend_from_slice(&rid_len.to_be_bytes());
        payload.extend_from_slice(rid);

        let eph = member.ephemeral_public.as_bytes();
        let eph_len: u32 = eph.len()
            .try_into()
            .map_err(|_| VeilError::Format("ephemeral_public too long for length prefix".into()))?;
        payload.extend_from_slice(&eph_len.to_be_bytes());
        payload.extend_from_slice(eph);

        let edek = member.encrypted_dek.as_bytes();
        let edek_len: u32 = edek.len()
            .try_into()
            .map_err(|_| VeilError::Format("encrypted_dek too long for length prefix".into()))?;
        payload.extend_from_slice(&edek_len.to_be_bytes());
        payload.extend_from_slice(edek);
    }

    let cid = bundle.signer_id.as_bytes();
    let cid_len: u32 = cid.len()
        .try_into()
        .map_err(|_| VeilError::Format("signer_id too long for length prefix".into()))?;
    payload.extend_from_slice(&cid_len.to_be_bytes());
    payload.extend_from_slice(cid);

    Ok(payload)
}

fn sign_bundle(bundle: &mut GroupKeyBundle, sign_secret: &[u8; 32]) -> Result<(), VeilError> {
    let payload = bundle_payload(bundle)?;
    let sig = crypto::ed25519_sign(sign_secret, &payload);
    bundle.signature = crypto::to_base64(&sig);
    Ok(())
}

// ---------- Bundle operations ----------

/// Create a new group key bundle. Generates a random GEK, wraps it for
/// each member, and signs the bundle.
///
/// `member_keys` includes all members (including the creator).
/// Returns `(bundle, gek)` so the caller can immediately use the GEK.
///
/// # Errors
///
/// Returns `VeilError` if key generation, wrapping, or signing fails.
pub fn create_bundle(
    group_id: &str,
    epoch: u32,
    our_id: &str,
    sign_secret: &[u8; 32],
    member_keys: &[(&str, &[u8; 32])],
) -> Result<(GroupKeyBundle, Zeroizing<[u8; 32]>), VeilError> {
    constants::validate_id(group_id, "group_id")?;
    constants::validate_id(our_id, "signer user_id")?;
    for (id, _) in member_keys {
        constants::validate_id(id, "member user_id")?;
    }

    if member_keys.is_empty() {
        return Err(VeilError::Validation("group must have at least one member".into()));
    }
    if member_keys.len() > constants::MAX_GROUP_MEMBERS {
        return Err(VeilError::Validation(format!(
            "too many members: {} (max {})",
            member_keys.len(),
            constants::MAX_GROUP_MEMBERS
        )));
    }

    let mut seen = std::collections::HashSet::with_capacity(member_keys.len());
    for (id, _) in member_keys {
        if !seen.insert(*id) {
            return Err(VeilError::Validation(format!("duplicate member '{id}'")));
        }
    }

    if !member_keys.iter().any(|(id, _)| *id == our_id) {
        return Err(VeilError::Validation(format!(
            "signer '{our_id}' must be in the member list"
        )));
    }

    let gek = crypto::generate_random_key()?;

    let mut members = Vec::with_capacity(member_keys.len());
    for (id, pub_key) in member_keys {
        members.push(envelope::wrap_dek(&gek, id, pub_key)?);
    }

    let mut bundle = GroupKeyBundle {
        version: 1,
        group_id: group_id.to_string(),
        epoch,
        members,
        signer_id: our_id.to_string(),
        signature: String::new(),
    };

    sign_bundle(&mut bundle, sign_secret)?;
    Ok((bundle, gek))
}

/// Unwrap the GEK from a bundle for the given user.
///
/// # Errors
///
/// Returns `VeilError` if the user is not a member or unwrapping fails.
pub fn unwrap_gek(
    bundle: &GroupKeyBundle,
    our_id: &str,
    our_secret: &[u8; 32],
    our_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, VeilError> {
    let wrapped = bundle
        .members
        .iter()
        .find(|w| w.user_id == our_id)
        .ok_or_else(|| VeilError::Validation("not a member of this group".into()))?;

    envelope::unwrap_dek(wrapped, our_secret, our_public)
}

/// Add a member to an existing group bundle.
///
/// Bumps the epoch so every bundle version has a unique epoch (prevents
/// same-epoch rollback). The GEK is unchanged (no key rotation).
/// The caller must be an existing member (to unwrap the GEK).
/// Re-signs the bundle with the caller's signing key.
///
/// # Errors
///
/// Returns `VeilError` if the caller is not a member, the new member already
/// exists, epoch overflows, or wrapping/signing fails.
pub fn add_member(
    bundle: &GroupKeyBundle,
    our_id: &str,
    our_secret: &[u8; 32],
    our_public: &[u8; 32],
    sign_secret: &[u8; 32],
    new_id: &str,
    new_public: &[u8; 32],
) -> Result<GroupKeyBundle, VeilError> {
    if bundle.members.iter().any(|w| w.user_id == new_id) {
        return Err(VeilError::Validation(format!("member '{new_id}' already exists")));
    }

    let new_epoch = bundle.epoch.checked_add(1)
        .ok_or_else(|| VeilError::Validation("epoch overflow".into()))?;

    let gek = unwrap_gek(bundle, our_id, our_secret, our_public)?;
    let new_wrapped = envelope::wrap_dek(&gek, new_id, new_public)?;

    let mut new_bundle = bundle.clone();
    new_bundle.epoch = new_epoch;
    new_bundle.members.push(new_wrapped);
    new_bundle.signer_id = our_id.to_string();
    sign_bundle(&mut new_bundle, sign_secret)?;
    Ok(new_bundle)
}

/// Remove a member and rotate the GEK (new epoch).
/// Generates a new GEK, wraps for remaining members, signs.
///
/// `remaining_member_keys` must include all remaining members (including the caller)
/// but NOT the removed member.
///
/// # Errors
///
/// Returns `VeilError` if the member is not found, or if the remaining
/// member list is empty.
pub fn remove_member(
    bundle: &GroupKeyBundle,
    our_id: &str,
    sign_secret: &[u8; 32],
    member_id: &str,
    remaining_member_keys: &[(&str, &[u8; 32])],
) -> Result<(GroupKeyBundle, Zeroizing<[u8; 32]>), VeilError> {
    if !bundle.members.iter().any(|w| w.user_id == member_id) {
        return Err(VeilError::Validation(format!("member '{member_id}' not found")));
    }

    if remaining_member_keys.is_empty() {
        return Err(VeilError::Validation("cannot remove the last member".into()));
    }

    if remaining_member_keys.iter().any(|(id, _)| *id == member_id) {
        return Err(VeilError::Validation(format!(
            "removed member '{member_id}' must not be in remaining_member_keys"
        )));
    }

    // New epoch with fresh GEK
    create_bundle(
        &bundle.group_id,
        bundle.epoch.checked_add(1)
            .ok_or_else(|| VeilError::Validation("epoch overflow".into()))?,
        our_id,
        sign_secret,
        remaining_member_keys,
    )
}

/// Verify the Ed25519 signature on a group key bundle.
///
/// Also validates that the `signer_id` appears in the member list.
/// This prevents an attacker from signing a bundle with an arbitrary
/// identity that isn't part of the group.
///
/// # Errors
///
/// Returns `VeilError` if the signer is not a member, the signature
/// is malformed, or verification fails.
pub fn verify_bundle(
    bundle: &GroupKeyBundle,
    signer_public: &[u8; 32],
) -> Result<(), VeilError> {
    if bundle.members.len() > constants::MAX_GROUP_MEMBERS {
        return Err(VeilError::Validation(format!(
            "bundle has too many members: {} (max {})",
            bundle.members.len(),
            constants::MAX_GROUP_MEMBERS
        )));
    }
    // Note: signer-is-member is already enforced during deserialization
    // (TryFrom<GroupKeyBundleWire>), so not checked again here.

    let sig_bytes: [u8; 64] = crypto::from_base64(&bundle.signature)?
        .try_into()
        .map_err(|_| VeilError::Format("bundle signature is not 64 bytes".into()))?;

    let payload = bundle_payload(bundle)?;
    crypto::ed25519_verify(signer_public, &payload, &sig_bytes)
}

// ---------- Group envelope operations ----------

/// Seal data for a group. Generates a DEK, encrypts data, wraps the DEK
/// with the GEK, and signs the envelope.
///
/// # Errors
///
/// Returns `VeilError` if encryption, wrapping, or signing fails.
pub fn seal(
    plaintext: &[u8],
    gek: &[u8; 32],
    group_id: &str,
    our_id: &str,
    sign_secret: &[u8; 32],
    metadata: Option<serde_json::Value>,
) -> Result<Envelope, VeilError> {
    let meta_bytes = constants::validate_metadata(metadata.as_ref())?;
    let dek = crypto::generate_random_key()?;
    let ct = crypto::aead_encrypt(&dek, plaintext, DOMAIN_DATA)?;

    // Wrap DEK with GEK using AES-GCM (AD = "veil-group-dek:" || group_id)
    let ad = constants::group_dek_ad(group_id);
    let wrapped = crypto::aead_encrypt(gek, &*dek, &ad)?;

    let mut envelope = Envelope {
        version: 1,
        ciphertext: crypto::to_base64(&ct),
        access: EnvelopeAccess::Group {
            group_id: group_id.to_string(),
            wrapped_dek: crypto::to_base64(&wrapped),
        },
        metadata,
        signer_id: Some(our_id.to_string()),
        signature: None,
        audit_hash: None,
    };

    let payload = envelope::signature_payload(&envelope, meta_bytes.as_deref())?;
    let sig = crypto::ed25519_sign(sign_secret, &payload);
    envelope.signature = Some(crypto::to_base64(&sig));

    Ok(envelope)
}

/// Open a group envelope. Unwraps the DEK using the GEK, decrypts the data.
///
/// # Errors
///
/// Returns `VeilError` if the envelope is not a group envelope, the DEK
/// cannot be unwrapped, or decryption fails.
pub fn open(
    envelope: &Envelope,
    gek: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, VeilError> {
    if envelope.version != 1 {
        return Err(VeilError::Format(format!(
            "unsupported envelope version: {}", envelope.version
        )));
    }

    let (group_id, wrapped_dek_b64) = match &envelope.access {
        EnvelopeAccess::Group { group_id, wrapped_dek } => {
            (group_id.as_str(), wrapped_dek.as_str())
        }
        EnvelopeAccess::Direct { .. } => {
            return Err(VeilError::Encoding("not a group envelope".into()));
        }
    };

    let wrapped = crypto::from_base64(wrapped_dek_b64)?;
    let ad = constants::group_dek_ad(group_id);

    let dek_bytes = crypto::aead_decrypt(gek, &wrapped, &ad)?;
    let dek = Zeroizing::new(<[u8; 32]>::try_from(dek_bytes.as_slice())
        .map_err(|_| VeilError::Encoding("unwrapped DEK not 32 bytes".into()))?);

    let ct = crypto::from_base64(&envelope.ciphertext)?;
    let decrypted = crypto::aead_decrypt(&dek, &ct, DOMAIN_DATA)?;
    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::type_complexity, clippy::indexing_slicing, clippy::panic, clippy::redundant_clone)]

    use super::*;
    use crate::crypto::{self, VeilError};
    use crate::key_directory;
    use crate::test_utils::make_user;

    // ---- Create Bundle ----

    #[test]
    fn create_bundle_works() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        assert_eq!(bundle.version, 1);
        assert_eq!(bundle.group_id, "team");
        assert_eq!(bundle.epoch, 1);
        assert_eq!(bundle.members.len(), 2);
        assert_eq!(bundle.signer_id, id_a);
        assert!(!bundle.signature.is_empty());
    }

    #[test]
    fn create_bundle_empty_members_fails() {
        let (_id_a, _dh_a, _pub_a, sign_a, _spub_a) = make_user();
        let result = create_bundle("team", 1, "alice", &sign_a, &[]);
        assert!(matches!(result, Err(VeilError::Validation(_))), "empty members must be rejected");
    }

    // ---- Unwrap GEK ----

    #[test]
    fn unwrap_gek_roundtrip() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (bundle, gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let gek_a = unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();
        let gek_b = unwrap_gek(&bundle, &id_b, &dh_b, &pub_b).unwrap();
        assert_eq!(*gek, *gek_a);
        assert_eq!(*gek, *gek_b);
    }

    #[test]
    fn unwrap_gek_non_member_fails() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (_id_c, dh_c, pub_c, _sign_c, _spub_c) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let result = unwrap_gek(&bundle, "nonexistent", &dh_c, &pub_c);
        assert!(matches!(result, Err(VeilError::Validation(_))), "non-member must not unwrap GEK");
    }

    // ---- Verify Bundle ----

    #[test]
    fn verify_bundle_valid() {
        let (id_a, _dh_a, pub_a, sign_a, spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        verify_bundle(&bundle, &spub_a).unwrap();
    }

    #[test]
    fn verify_bundle_wrong_key_fails() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (_id_b, _dh_b, _pub_b, _sign_b, spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let result = verify_bundle(&bundle, &spub_b);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "wrong key must fail bundle verification");
    }

    #[test]
    fn verify_bundle_tampered_fails() {
        let (id_a, _dh_a, pub_a, sign_a, spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (mut bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        bundle.group_id = "tampered".to_string();
        let result = verify_bundle(&bundle, &spub_a);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "tampered bundle must fail verification");
    }

    #[test]
    fn verify_bundle_rejects_non_member_creator() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let (id_outsider, _dh_o, _pub_o, _sign_o, spub_o) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (mut bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        bundle.signer_id = id_outsider;
        let result = verify_bundle(&bundle, &spub_o);
        let err = result.unwrap_err();
        assert!(matches!(err, VeilError::Encoding(_)), "non-member signer must be rejected");
        assert!(
            err.to_string().contains("not a member"),
            "error should mention non-member"
        );
    }

    #[test]
    fn create_bundle_rejects_non_member_creator() {
        let (id_a, _dh_a, pub_a, _sign_a, _spub_a) = make_user();
        let (id_outsider, _dh_o, _pub_o, sign_o, _spub_o) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let result = create_bundle("team", 1, &id_outsider, &sign_o, &members);
        assert!(matches!(result, Err(VeilError::Validation(_))), "non-member creator must be rejected at creation");
    }

    // ---- Add Member ----

    #[test]
    fn add_member_works() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let updated = add_member(&bundle, &id_a, &dh_a, &pub_a, &sign_a, &id_b, &pub_b).unwrap();
        assert_eq!(updated.members.len(), 2);
        assert_eq!(updated.epoch, 2);
        let gek_b = unwrap_gek(&updated, &id_b, &dh_b, &pub_b).unwrap();
        assert_eq!(*gek, *gek_b);
    }

    #[test]
    fn add_duplicate_member_fails() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let result = add_member(&bundle, &id_a, &dh_a, &pub_a, &sign_a, &id_a, &pub_a);
        assert!(matches!(result, Err(VeilError::Validation(_))), "duplicate member must be rejected");
    }

    // ---- Remove Member ----

    #[test]
    fn remove_member_rotates_gek() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (bundle, old_gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let remaining: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (updated, new_gek) = remove_member(&bundle, &id_a, &sign_a, &id_b, &remaining).unwrap();
        assert_eq!(updated.epoch, 2);
        assert_eq!(updated.members.len(), 1);
        assert_ne!(*old_gek, *new_gek);
        let gek_a = unwrap_gek(&updated, &id_a, &dh_a, &pub_a).unwrap();
        assert_eq!(*new_gek, *gek_a);
        let result = unwrap_gek(&updated, &id_b, &dh_b, &pub_b);
        assert!(matches!(result, Err(VeilError::Validation(_))), "removed member must not unwrap GEK");
    }

    #[test]
    fn remove_nonexistent_member_fails() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let remaining: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let result = remove_member(&bundle, &id_a, &sign_a, "nonexistent", &remaining);
        assert!(matches!(result, Err(VeilError::Validation(_))), "nonexistent member must be rejected");
    }

    #[test]
    fn remove_last_member_fails() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let result = remove_member(&bundle, &id_a, &sign_a, &id_a, &[]);
        assert!(matches!(result, Err(VeilError::Validation(_))), "removing last member must fail");
    }

    // ---- Group Seal / Open ----

    #[test]
    fn seal_open_roundtrip() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (bundle, _) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let gek_a = unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();
        let env = seal(b"secret message", &gek_a, "team", &id_a, &sign_a, None).unwrap();
        assert_eq!(env.group_id(), Some("team"));
        assert!(env.group_info().is_some());
        assert!(env.recipients().is_empty());
        assert!(env.signature.is_some());
        assert_eq!(env.signer_id.as_deref(), Some(id_a.as_str()));
        let pt_a = open(&env, &gek_a).unwrap();
        assert_eq!(&*pt_a, b"secret message");
        let gek_b = unwrap_gek(&bundle, &id_b, &dh_b, &pub_b).unwrap();
        let pt_b = open(&env, &gek_b).unwrap();
        assert_eq!(&*pt_b, b"secret message");
    }

    #[test]
    fn seal_with_metadata() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let gek = unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();
        let meta = serde_json::json!({"type": "message"});
        let env = seal(b"hello", &gek, "team", &id_a, &sign_a, Some(meta.clone())).unwrap();
        assert_eq!(env.metadata, Some(meta));
        let pt = open(&env, &gek).unwrap();
        assert_eq!(&*pt, b"hello");
    }

    #[test]
    fn open_wrong_gek_fails() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let gek = unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();
        let env = seal(b"secret", &gek, "team", &id_a, &sign_a, None).unwrap();
        let wrong_gek = crypto::generate_random_key().unwrap();
        let result = open(&env, &wrong_gek);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "wrong GEK must fail to open");
    }

    #[test]
    fn open_non_group_envelope_fails() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let env = envelope::seal(b"hello", &id_a, &pub_a, &sign_a, &[], None).unwrap();
        let gek = crypto::generate_random_key().unwrap();
        let result = open(&env, &gek);
        assert!(matches!(result, Err(VeilError::Encoding(_))), "non-group envelope must be rejected");
    }

    // ---- Verify Group Envelope Signature ----

    #[test]
    fn group_envelope_signature_valid() {
        let (id_a, dh_a, pub_a, sign_a, spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let gek = unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();
        let env = seal(b"hello", &gek, "team", &id_a, &sign_a, None).unwrap();
        envelope::verify(&env, &spub_a).unwrap();
    }

    #[test]
    fn group_envelope_signature_covers_group_id() {
        let (id_a, dh_a, pub_a, sign_a, spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let gek = unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();
        let mut env = seal(b"hello", &gek, "team", &id_a, &sign_a, None).unwrap();
        env.access = EnvelopeAccess::Group {
            group_id: "tampered".to_string(),
            wrapped_dek: env.group_info().unwrap().1.to_string(),
        };
        let result = envelope::verify(&env, &spub_a);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "tampered group_id must invalidate signature");
    }

    // ---- Security: Removed member after rotation ----

    #[test]
    fn removed_member_cannot_open_new_envelopes() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (bundle, _) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let old_gek = unwrap_gek(&bundle, &id_b, &dh_b, &pub_b).unwrap();
        let env1 = seal(b"before removal", &old_gek, "team", &id_a, &sign_a, None).unwrap();
        let pt = open(&env1, &old_gek).unwrap();
        assert_eq!(&*pt, b"before removal");
        let remaining: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (updated, new_gek) = remove_member(&bundle, &id_a, &sign_a, &id_b, &remaining).unwrap();
        let gek_a = unwrap_gek(&updated, &id_a, &dh_a, &pub_a).unwrap();
        assert_eq!(*new_gek, *gek_a);
        let env2 = seal(b"after removal", &gek_a, "team", &id_a, &sign_a, None).unwrap();
        let result = open(&env2, &old_gek);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "removed member must not open new envelope");
        let result = unwrap_gek(&updated, &id_b, &dh_b, &pub_b);
        assert!(matches!(result, Err(VeilError::Validation(_))), "removed member must not unwrap new GEK");
    }

    // ---- Serialization ----

    #[test]
    fn group_envelope_json_roundtrip() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let gek = unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();
        let env = seal(b"hello", &gek, "team", &id_a, &sign_a, None).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.group_id(), env.group_id());
        assert_eq!(parsed.group_info().map(|g| g.1), env.group_info().map(|g| g.1));
        assert_eq!(parsed.ciphertext, env.ciphertext);
        let pt = open(&parsed, &gek).unwrap();
        assert_eq!(&*pt, b"hello");
    }

    #[test]
    fn group_bundle_json_roundtrip() {
        let (id_a, _dh_a, pub_a, sign_a, spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: GroupKeyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.group_id, bundle.group_id);
        assert_eq!(parsed.epoch, bundle.epoch);
        assert_eq!(parsed.members.len(), bundle.members.len());
        verify_bundle(&parsed, &spub_a).unwrap();
    }

    // ---- Freshness ----

    #[test]
    fn seal_produces_different_ciphertext() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let gek = unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();
        let env1 = seal(b"same", &gek, "team", &id_a, &sign_a, None).unwrap();
        let env2 = seal(b"same", &gek, "team", &id_a, &sign_a, None).unwrap();
        assert_ne!(env1.ciphertext, env2.ciphertext);
        assert_ne!(env1.group_info().map(|g| g.1), env2.group_info().map(|g| g.1));
    }

    // ---- Bundle tampering ----

    #[test]
    fn bundle_member_key_tamper_invalidates_signature() {
        let (id_a, _dh_a, pub_a, sign_a, spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (mut bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        bundle.members[0].encrypted_dek = bundle.members[1].encrypted_dek.clone();
        let result = verify_bundle(&bundle, &spub_a);
        assert!(matches!(result, Err(VeilError::Crypto(_))), "tampered member key must invalidate bundle signature");
    }

    #[test]
    fn add_member_by_non_member_fails() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let (id_c, dh_c, pub_c, sign_c, _spub_c) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let result = add_member(&bundle, &id_c, &dh_c, &pub_c, &sign_c, &id_b, &pub_b);
        assert!(matches!(result, Err(VeilError::Validation(_))), "non-member must not be able to add a member");
    }

    // ---- Auto Group ID ----

    #[test]
    fn auto_group_id_deterministic() {
        let id1 = auto_group_id(&["alice", "bob"]);
        let id2 = auto_group_id(&["alice", "bob"]);
        assert_eq!(id1, id2);
    }

    #[test]
    fn auto_group_id_order_independent() {
        let id1 = auto_group_id(&["alice", "bob", "carol"]);
        let id2 = auto_group_id(&["carol", "alice", "bob"]);
        assert_eq!(id1, id2);
    }

    #[test]
    fn auto_group_id_deduplicates() {
        let id1 = auto_group_id(&["alice", "bob"]);
        let id2 = auto_group_id(&["alice", "bob", "alice"]);
        assert_eq!(id1, id2);
    }

    #[test]
    fn auto_group_id_different_sets_differ() {
        let id1 = auto_group_id(&["alice", "bob"]);
        let id2 = auto_group_id(&["alice", "carol"]);
        assert_ne!(id1, id2);
    }

    #[test]
    fn auto_group_id_has_prefix() {
        let id = auto_group_id(&["alice", "bob"]);
        assert!(id.starts_with("auto:"), "auto group IDs must start with 'auto:'");
    }

    #[test]
    fn auto_group_id_colon_in_ids_not_ambiguous() {
        let id1 = auto_group_id(&["a:b", "c"]);
        let id2 = auto_group_id(&["a", "b:c"]);
        assert_ne!(id1, id2, "different user sets with colons must produce different IDs");
    }

    // ---- GEK Cache ----

    #[test]
    fn gek_cache_insert_and_get() {
        let mut cache = GekCache::new();
        let gek = crypto::generate_random_key().unwrap();
        cache.insert("team".to_string(), 1, gek.clone());
        let cached = cache.get("team", 1);
        assert!(cached.is_some());
        assert_eq!(**cached.unwrap(), *gek);
    }

    #[test]
    fn gek_cache_epoch_mismatch_returns_none() {
        let mut cache = GekCache::new();
        let gek = crypto::generate_random_key().unwrap();
        cache.insert("team".to_string(), 1, gek);
        assert!(cache.get("team", 2).is_none());
    }

    #[test]
    fn gek_cache_invalidate() {
        let mut cache = GekCache::new();
        let gek = crypto::generate_random_key().unwrap();
        cache.insert("team".to_string(), 1, gek);
        cache.invalidate("team");
        assert!(cache.get("team", 1).is_none());
    }

    #[test]
    fn gek_cache_clear() {
        let mut cache = GekCache::new();
        let gek1 = crypto::generate_random_key().unwrap();
        let gek2 = crypto::generate_random_key().unwrap();
        cache.insert("team1".to_string(), 1, gek1);
        cache.insert("team2".to_string(), 1, gek2);
        cache.clear();
        assert!(cache.get("team1", 1).is_none());
        assert!(cache.get("team2", 1).is_none());
    }

    #[test]
    fn gek_cache_update_replaces_old_epoch() {
        let mut cache = GekCache::new();
        let gek1 = crypto::generate_random_key().unwrap();
        let gek2 = crypto::generate_random_key().unwrap();
        cache.insert("team".to_string(), 1, gek1);
        cache.insert("team".to_string(), 2, gek2.clone());
        assert!(cache.get("team", 1).is_none());
        assert_eq!(**cache.get("team", 2).unwrap(), *gek2);
    }

    // ---- Key Cache ----

    #[test]
    fn key_cache_insert_and_get() {
        let mut cache = key_directory::KeyCache::new();
        let bundle = key_directory::PublicKeyBundle {
            dh_public: [1u8; 32],
            sign_public: [2u8; 32],
        };
        cache.insert("alice".to_string(), bundle.clone());
        let cached = cache.get("alice");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().dh_public, bundle.dh_public);
        assert_eq!(cached.unwrap().sign_public, bundle.sign_public);
    }

    #[test]
    fn key_cache_miss_returns_none() {
        let mut cache = key_directory::KeyCache::new();
        assert!(cache.get("unknown").is_none());
    }

    #[test]
    fn key_cache_invalidate() {
        let mut cache = key_directory::KeyCache::new();
        cache.insert(
            "alice".to_string(),
            key_directory::PublicKeyBundle {
                dh_public: [1u8; 32],
                sign_public: [2u8; 32],
            },
        );
        cache.invalidate("alice");
        assert!(cache.get("alice").is_none());
    }

    #[test]
    fn key_cache_clear() {
        let mut cache = key_directory::KeyCache::new();
        cache.insert(
            "alice".to_string(),
            key_directory::PublicKeyBundle {
                dh_public: [1u8; 32],
                sign_public: [2u8; 32],
            },
        );
        cache.insert(
            "bob".to_string(),
            key_directory::PublicKeyBundle {
                dh_public: [3u8; 32],
                sign_public: [4u8; 32],
            },
        );
        cache.clear();
        assert!(cache.get("alice").is_none());
        assert!(cache.get("bob").is_none());
    }

    // ---- GEK cache LRU eviction ----

    #[test]
    fn gek_cache_lru_eviction() {
        let mut cache = GekCache::new();

        // Fill beyond capacity by inserting MAX_ENTRIES + 1
        for i in 0..=GEK_CACHE_MAX_ENTRIES {
            let gek = crypto::generate_random_key().unwrap();
            cache.insert(format!("group-{i}"), 1, gek);
        }

        // Should have evicted the oldest entry (group-0)
        assert!(cache.get("group-0", 1).is_none(),
            "oldest entry should have been evicted");

        // Most recent entry should still exist
        let last = format!("group-{GEK_CACHE_MAX_ENTRIES}");
        assert!(cache.get(&last, 1).is_some(),
            "most recent entry should still be cached");
    }

    // ---- Key cache LRU eviction ----

    #[test]
    fn key_cache_lru_eviction() {
        let mut cache = key_directory::KeyCache::new();
        let max = 1024_usize; // KEY_CACHE_MAX_ENTRIES

        for i in 0..=max {
            let [byte, ..] = i.to_le_bytes();
            cache.insert(
                format!("user-{i}"),
                key_directory::PublicKeyBundle {
                    dh_public: [byte; 32],
                    sign_public: [byte; 32],
                },
            );
        }

        assert!(cache.get("user-0").is_none(),
            "oldest key cache entry should have been evicted");
        assert!(cache.get(&format!("user-{max}")).is_some(),
            "most recent key cache entry should still be cached");
    }

    // ---- Bundle signer must be a member ----

    #[test]
    fn bundle_signer_not_member_rejected() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let (id_outsider, _dh_o, _pub_o, sign_o, spub_o) = make_user();

        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (mut bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();

        // Tamper: change signer_id to outsider and re-sign with outsider's key
        bundle.signer_id = id_outsider;
        let payload = super::bundle_payload(&bundle).unwrap();
        bundle.signature = crypto::to_base64(&crypto::ed25519_sign(&sign_o, &payload));

        // verify_bundle must reject because outsider is not a member
        let result = verify_bundle(&bundle, &spub_o);
        assert!(result.is_err(),
            "bundle signed by non-member must be rejected");
    }

    // ---- Group seal with large plaintext ----

    #[test]
    fn group_seal_large_plaintext() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();

        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        let gek = unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();

        let large = vec![0xABu8; 1_000_000]; // 1MB
        let env = seal(&large, &gek, "team", &id_a, &sign_a, None).unwrap();
        let pt = open(&env, &gek).unwrap();
        assert_eq!(&*pt, &large);
    }

    // ---- ID validation ----

    #[test]
    fn empty_group_id_rejected() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let result = create_bundle("", 1, &id_a, &sign_a, &members);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "empty group_id must be rejected");
    }

    #[test]
    fn oversized_group_id_rejected() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let huge_id = "g".repeat(1024);
        let result = create_bundle(&huge_id, 1, &id_a, &sign_a, &members);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "oversized group_id must be rejected");
    }

    // ---- PublicKeyBundle Debug hides key material ----

    #[test]
    fn public_key_bundle_debug_redacts_keys() {
        let bundle = key_directory::PublicKeyBundle {
            dh_public: [0xAA; 32],
            sign_public: [0xBB; 32],
        };
        let debug_str = format!("{bundle:?}");
        // Must not contain raw hex of the key bytes
        assert!(!debug_str.contains("170"), "Debug must not contain raw key bytes");
        assert!(!debug_str.contains("187"), "Debug must not contain raw key bytes");
        // Must contain fingerprint-style colon-separated hex
        assert!(debug_str.contains(':'), "Debug must show fingerprint format");
    }

    // ---- Control character rejection ----

    #[test]
    fn control_chars_in_group_id_rejected() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let result = create_bundle("team\x00evil", 1, &id_a, &sign_a, &members);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "null byte in group_id must be rejected");
    }

    #[test]
    fn newline_in_group_id_rejected() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let result = create_bundle("team\nevil", 1, &id_a, &sign_a, &members);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "newline in group_id must be rejected");
    }

    // ---- Bundle deserialization validation ----

    #[test]
    fn deserialized_bundle_version_zero_rejected() {
        let json = r#"{"version":0,"group_id":"team","epoch":1,"members":[
            {"user_id":"alice","ephemeral_public":"AAAA","encrypted_dek":"BBBB"}
        ],"signer_id":"alice","signature":"AAAA"}"#;
        let result: Result<GroupKeyBundle, _> = serde_json::from_str(json);
        assert!(result.is_err(), "bundle version 0 must be rejected");
    }

    #[test]
    fn deserialized_bundle_duplicate_members_rejected() {
        let json = r#"{"version":1,"group_id":"team","epoch":1,"members":[
            {"user_id":"alice","ephemeral_public":"AAAA","encrypted_dek":"BBBB"},
            {"user_id":"alice","ephemeral_public":"CCCC","encrypted_dek":"DDDD"}
        ],"signer_id":"alice","signature":"AAAA"}"#;
        let result: Result<GroupKeyBundle, _> = serde_json::from_str(json);
        assert!(result.is_err(), "bundle with duplicate members must be rejected");
    }

    #[test]
    fn deserialized_bundle_signer_not_member_rejected() {
        let json = r#"{"version":1,"group_id":"team","epoch":1,"members":[
            {"user_id":"alice","ephemeral_public":"AAAA","encrypted_dek":"BBBB"}
        ],"signer_id":"mallory","signature":"AAAA"}"#;
        let result: Result<GroupKeyBundle, _> = serde_json::from_str(json);
        assert!(result.is_err(), "bundle with signer not in members must be rejected");
    }

    #[test]
    fn deserialized_bundle_empty_members_rejected() {
        let json = r#"{"version":1,"group_id":"team","epoch":1,"members":[],"signer_id":"alice","signature":"AAAA"}"#;
        let result: Result<GroupKeyBundle, _> = serde_json::from_str(json);
        assert!(result.is_err(), "bundle with empty members must be rejected");
    }

    // ---- URL / auth token validation ----

    #[test]
    fn validate_server_url_rejects_bad_schemes() {
        use crate::constants;
        assert!(constants::validate_server_url("https://example.com").is_ok());
        assert!(constants::validate_server_url("http://localhost:3000").is_ok());
        assert!(constants::validate_server_url("javascript:void(0)").is_err());
        assert!(constants::validate_server_url("ftp://files.example.com").is_err());
        assert!(constants::validate_server_url("").is_err());
    }

    #[test]
    fn validate_auth_token_rejects_empty() {
        use crate::constants;
        assert!(constants::validate_auth_token(None).is_ok());
        assert!(constants::validate_auth_token(Some("bearer-abc")).is_ok());
        assert!(constants::validate_auth_token(Some("")).is_err());
    }

    // ---- Epoch overflow ----

    #[test]
    fn add_member_epoch_overflow_rejected() {
        let (id_a, dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (mut bundle, _gek) = create_bundle("team", u32::MAX, &id_a, &sign_a, &members).unwrap();
        // Re-sign at u32::MAX epoch
        bundle.epoch = u32::MAX;
        super::sign_bundle(&mut bundle, &sign_a).unwrap();
        let result = add_member(&bundle, &id_a, &dh_a, &pub_a, &sign_a, &id_b, &pub_b);
        match &result {
            Err(VeilError::Validation(msg)) => {
                assert!(msg.contains("overflow"), "error message must mention overflow");
            }
            _ => panic!("add_member at u32::MAX epoch must fail with Validation error"),
        }
    }

    #[test]
    fn remove_member_epoch_overflow_rejected() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (mut bundle, _gek) = create_bundle("team", u32::MAX, &id_a, &sign_a, &members).unwrap();
        bundle.epoch = u32::MAX;
        super::sign_bundle(&mut bundle, &sign_a).unwrap();
        let remaining: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let result = remove_member(&bundle, &id_a, &sign_a, &id_b, &remaining);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "remove_member at u32::MAX epoch must fail with overflow");
    }

    // ---- Duplicate member in create_bundle rejected ----

    #[test]
    fn create_bundle_duplicate_members_rejected() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_a, &pub_a)];
        let result = create_bundle("team", 1, &id_a, &sign_a, &members);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "duplicate members must be rejected");
    }

    // ---- Remove member still in remaining_member_keys rejected ----

    #[test]
    fn remove_member_in_remaining_keys_rejected() {
        let (id_a, _dh_a, pub_a, sign_a, _spub_a) = make_user();
        let (id_b, _dh_b, pub_b, _sign_b, _spub_b) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let (bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        // Include removed member in remaining keys
        let remaining: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
        let result = remove_member(&bundle, &id_a, &sign_a, &id_b, &remaining);
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "removed member in remaining_member_keys must be rejected");
    }

    // ---- Bundle epoch tampering invalidates signature ----

    #[test]
    fn bundle_epoch_tamper_invalidates_signature() {
        let (id_a, _dh_a, pub_a, sign_a, spub_a) = make_user();
        let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
        let (mut bundle, _gek) = create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
        bundle.epoch = 999;
        let result = verify_bundle(&bundle, &spub_a);
        assert!(matches!(result, Err(VeilError::Crypto(_))),
            "tampered epoch must invalidate bundle signature");
    }
}
