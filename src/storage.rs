use crate::crypto::{from_base64, to_base64, VeilError};
use crate::webcrypto_shim;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

fn get_local_storage() -> Result<web_sys::Storage, VeilError> {
    let window =
        web_sys::window().ok_or_else(|| VeilError::Storage("no global window object".into()))?;
    window
        .local_storage()
        .map_err(|_| VeilError::Storage("localStorage access denied".into()))?
        .ok_or_else(|| VeilError::Storage("localStorage not available".into()))
}

fn store_json(key: &str, value: &impl Serialize) -> Result<(), VeilError> {
    let storage = get_local_storage()?;
    let json = serde_json::to_string(value)
        .map_err(|e| VeilError::Encoding(format!("json encode: {e}")))?;
    storage
        .set_item(key, &json)
        .map_err(|_| VeilError::Storage("localStorage set_item failed".into()))
}

fn load_json<T: for<'de> Deserialize<'de>>(key: &str) -> Result<Option<T>, VeilError> {
    let storage = get_local_storage()?;
    let json = storage
        .get_item(key)
        .map_err(|_| VeilError::Storage("localStorage get_item failed".into()))?;
    match json {
        Some(j) => {
            let val = serde_json::from_str(&j)
                .map_err(|e| VeilError::Encoding(format!("json decode: {e}")))?;
            Ok(Some(val))
        }
        None => Ok(None),
    }
}

// ---------- Generic encrypted save/load ----------

/// Encrypted format prefix. Stored as `"E:" + base64(wrapped)`.
const ENCRYPTED_PREFIX: &str = "E:";

/// Save data to `localStorage`, encrypting with `WebCrypto`.
///
/// Requires `IndexedDB` for the wrapping key. Returns an error if
/// `IndexedDB` is unavailable — data is never stored as plaintext.
async fn save_encrypted(
    ls_key: &str,
    ad: &str,
    data: &[u8],
) -> Result<(), VeilError> {
    let storage = get_local_storage()?;

    if !webcrypto_shim::is_idb_available().await {
        return Err(VeilError::Environment(
            "IndexedDB is required for encrypted storage but is unavailable.".into(),
        ));
    }

    let crypto_key = webcrypto_shim::ensure_wrapping_key().await?;
    let wrapped = webcrypto_shim::wrap_secret(&crypto_key, data, ad).await?;
    let value = format!("{ENCRYPTED_PREFIX}{}", to_base64(&wrapped));
    storage
        .set_item(ls_key, &value)
        .map_err(|_| VeilError::Storage("localStorage set_item failed".into()))
}

/// Load data from `localStorage`, decrypting the encrypted format.
async fn load_encrypted(
    ls_key: &str,
    ad: &str,
) -> Result<Option<Vec<u8>>, VeilError> {
    let storage = get_local_storage()?;
    let val = storage
        .get_item(ls_key)
        .map_err(|_| VeilError::Storage("localStorage get_item failed".into()))?;

    let Some(raw) = val else {
        return Ok(None);
    };

    if let Some(wrapped_b64) = raw.strip_prefix(ENCRYPTED_PREFIX) {
        let wrapped_bytes = from_base64(wrapped_b64)?;
        let crypto_key = webcrypto_shim::ensure_wrapping_key().await.map_err(|_| {
            VeilError::Crypto(format!(
                "cannot decrypt '{ls_key}': wrapping key not found in IndexedDB"
            ))
        })?;
        let plaintext = webcrypto_shim::unwrap_secret(&crypto_key, &wrapped_bytes, ad).await?;
        Ok(Some(plaintext))
    } else {
        // Unrecognized format — reject rather than silently accepting plaintext
        Err(VeilError::Format(format!(
            "'{ls_key}' is not in encrypted format (missing '{ENCRYPTED_PREFIX}' prefix)"
        )))
    }
}

/// Remove an entry from `localStorage`.
fn clear_entry(ls_key: &str) -> Result<(), VeilError> {
    let storage = get_local_storage()?;
    storage
        .remove_item(ls_key)
        .map_err(|_| VeilError::Storage("localStorage removeItem failed".into()))
}

// ---------- Identity key ----------

const COMBINED_KEY_LEN: usize = 64; // dh_secret(32) + sign_secret(32)

/// Encrypted identity: v2 format with both DH and signing secrets.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    v: u8,
    wrapped: String,
}

/// Keys returned from storage: DH secret + signing secret.
pub struct StoredKeys {
    pub dh_secret: Zeroizing<[u8; 32]>,
    pub sign_secret: Zeroizing<[u8; 32]>,
}

/// Combine both secrets into a 64-byte blob for wrapping.
fn combine_secrets(dh_secret: &[u8; 32], sign_secret: &[u8; 32]) -> Zeroizing<[u8; COMBINED_KEY_LEN]> {
    let mut combined = Zeroizing::new([0u8; COMBINED_KEY_LEN]);
    let (dh_half, sign_half) = combined.split_at_mut(32);
    dh_half.copy_from_slice(dh_secret);
    sign_half.copy_from_slice(sign_secret);
    combined
}

/// Split a 64-byte blob into `(dh_secret, sign_secret)`.
fn split_secrets(combined: &[u8; COMBINED_KEY_LEN]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut dh = Zeroizing::new([0u8; 32]);
    let mut sign = Zeroizing::new([0u8; 32]);
    let (dh_half, sign_half) = combined.split_at(32);
    dh.copy_from_slice(dh_half);
    sign.copy_from_slice(sign_half);
    (dh, sign)
}

/// Save identity keys with at-rest encryption via `WebCrypto`.
/// Wraps `dh_secret(32) || sign_secret(32)` as a single 64-byte blob.
///
/// # Errors
///
/// Returns `VeilError` if `IndexedDB` is unavailable. Identity keys are
/// never stored as plaintext — this prevents silent downgrade to
/// unprotected storage under XSS.
pub async fn save_identity_encrypted(
    user_id: &str,
    dh_secret: &[u8; 32],
    sign_secret: &[u8; 32],
) -> Result<(), VeilError> {
    if !webcrypto_shim::is_idb_available().await {
        return Err(VeilError::Environment(
            "IndexedDB is required for secure key storage but is unavailable. \
             Enable IndexedDB or use a supported browser."
                .into(),
        ));
    }

    let combined = combine_secrets(dh_secret, sign_secret);
    let crypto_key = webcrypto_shim::ensure_wrapping_key().await?;
    let ad = format!("veil-identity:{user_id}");
    let wrapped_bytes =
        webcrypto_shim::wrap_secret(&crypto_key, &*combined, &ad).await?;

    let stored = StoredIdentity {
        v: 2,
        wrapped: to_base64(&wrapped_bytes),
    };
    store_json(&format!("veil:identity:{user_id}"), &stored)
}

/// Load identity keys (v2 encrypted format).
///
/// Returns `Some(StoredKeys)` or `None` if no identity is stored.
///
/// # Errors
///
/// Returns `VeilError` if the stored format is unrecognized, the
/// wrapping key is unavailable, or decryption fails.
pub async fn load_identity_encrypted(
    user_id: &str,
) -> Result<Option<StoredKeys>, VeilError> {
    let key = format!("veil:identity:{user_id}");
    let stored: Option<StoredIdentity> = load_json(&key)?;

    let Some(stored) = stored else {
        return Ok(None);
    };

    if stored.v != 2 {
        return Err(VeilError::Format(format!(
            "unsupported identity format version: {}", stored.v
        )));
    }

    let wrapped_bytes = from_base64(&stored.wrapped)?;

    let crypto_key = webcrypto_shim::ensure_wrapping_key().await.map_err(|_| {
        VeilError::Crypto(
            "cannot decrypt identity: wrapping key not found in IndexedDB. \
             Use importIdentity() to restore from backup."
                .into(),
        )
    })?;

    let ad = format!("veil-identity:{user_id}");
    let plaintext =
        webcrypto_shim::unwrap_secret(&crypto_key, &wrapped_bytes, &ad).await?;

    if plaintext.len() != COMBINED_KEY_LEN {
        return Err(VeilError::Format(format!(
            "unexpected identity blob size: {} bytes (expected {COMBINED_KEY_LEN})",
            plaintext.len()
        )));
    }

    let combined: [u8; COMBINED_KEY_LEN] = plaintext
        .try_into()
        .map_err(|_| VeilError::Format("unexpected key blob size".into()))?;
    let (dh_secret, sign_secret) = split_secrets(&combined);
    Ok(Some(StoredKeys { dh_secret, sign_secret }))
}

// ---------- TOFU key pins (combined) ----------

const COMBINED_PIN_LEN: usize = 64; // dh_public(32) + sign_public(32)

/// Save both DH and signing public keys as a single atomic pin.
/// Uses one `localStorage` write to avoid half-pinned state on crash.
pub async fn save_combined_key_pin(
    user_id: &str,
    dh_public: &[u8; 32],
    sign_public: &[u8; 32],
) -> Result<(), VeilError> {
    let ls_key = format!("veil:pin:{user_id}");
    let ad = format!("veil-pin:{user_id}");
    let mut combined = [0u8; COMBINED_PIN_LEN];
    combined[..32].copy_from_slice(dh_public);
    combined[32..].copy_from_slice(sign_public);
    save_encrypted(&ls_key, &ad, &combined).await
}

/// Load the combined key pin.
///
/// Returns `Some((dh_public, sign_public))` or `None` on first contact.
///
/// # Errors
///
/// Returns `VeilError` if the stored pin has an unexpected size or
/// decryption fails.
pub async fn load_combined_key_pin(
    user_id: &str,
) -> Result<Option<([u8; 32], [u8; 32])>, VeilError> {
    let ls_key = format!("veil:pin:{user_id}");
    let ad = format!("veil-pin:{user_id}");

    let Some(data) = load_encrypted(&ls_key, &ad).await? else {
        return Ok(None);
    };

    if data.len() != COMBINED_PIN_LEN {
        return Err(VeilError::Format(format!(
            "pinned key blob has unexpected size: {} bytes (expected {COMBINED_PIN_LEN})",
            data.len()
        )));
    }

    let mut dh = [0u8; 32];
    let mut sign = [0u8; 32];
    dh.copy_from_slice(data.get(..32).ok_or_else(|| VeilError::Format("combined pin too short".into()))?);
    sign.copy_from_slice(data.get(32..).ok_or_else(|| VeilError::Format("combined pin too short".into()))?);
    Ok(Some((dh, sign)))
}

/// Clear TOFU pins for a user.
pub fn clear_all_key_pins(user_id: &str) -> Result<(), VeilError> {
    clear_entry(&format!("veil:pin:{user_id}"))
}

// ---------- Group epoch persistence ----------

/// Save the last-seen epoch for a group, encrypted if possible.
pub async fn save_group_epoch(group_id: &str, epoch: u32) -> Result<(), VeilError> {
    let ls_key = format!("veil:epoch:{group_id}");
    let ad = format!("veil-epoch:{group_id}");
    save_encrypted(&ls_key, &ad, &epoch.to_be_bytes()).await
}

/// Load the last-seen epoch for a group. Returns `None` if no epoch
/// has been persisted yet (first contact with group).
pub async fn load_group_epoch(group_id: &str) -> Result<Option<u32>, VeilError> {
    let ls_key = format!("veil:epoch:{group_id}");
    let ad = format!("veil-epoch:{group_id}");
    load_encrypted(&ls_key, &ad).await?
        .map(|v| {
            let bytes: [u8; 4] = v
                .try_into()
                .map_err(|_| VeilError::Format("stored epoch is not 4 bytes".into()))?;
            Ok(u32::from_be_bytes(bytes))
        })
        .transpose()
}

/// Clear the persisted epoch for a group.
pub fn clear_group_epoch(group_id: &str) -> Result<(), VeilError> {
    clear_entry(&format!("veil:epoch:{group_id}"))
}

// ---------- Known group signers ----------

/// Save the set of known bundle signers for a group.
pub async fn save_known_signers(group_id: &str, signers: &[String]) -> Result<(), VeilError> {
    let json = serde_json::to_string(signers)
        .map_err(|e| VeilError::Encoding(format!("json encode signers: {e}")))?;
    let ls_key = format!("veil:signers:{group_id}");
    let ad = format!("veil-signers:{group_id}");
    save_encrypted(&ls_key, &ad, json.as_bytes()).await
}

/// Load the set of known bundle signers for a group.
/// Returns `None` on first contact with the group.
pub async fn load_known_signers(group_id: &str) -> Result<Option<Vec<String>>, VeilError> {
    let ls_key = format!("veil:signers:{group_id}");
    let ad = format!("veil-signers:{group_id}");
    load_encrypted(&ls_key, &ad).await?
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|e| VeilError::Encoding(format!("json decode signers: {e}")))
        })
        .transpose()
}

/// Clear the known signers for a group.
pub fn clear_known_signers(group_id: &str) -> Result<(), VeilError> {
    clear_entry(&format!("veil:signers:{group_id}"))
}
