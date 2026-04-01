use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::constants::DOMAIN_EXPORT;
use crate::crypto::{self, VeilError};
use crate::keys::IdentityKeyPair;
use crate::storage;

use super::VeilClient;

type SecretPair = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

const PBKDF2_ITERATIONS: u32 = 1_000_000;
const EXPORT_SALT_LEN: usize = 16;
/// Minimum export blob: version(1) + salt(16) + nonce(12) + tag(16) = 45 bytes.
const EXPORT_BLOB_MIN_LEN: usize = 1 + EXPORT_SALT_LEN + 12 + 16;
const EXPORT_PASSWORD_MIN_LEN: usize = 16;

#[wasm_bindgen]
impl VeilClient {
    /// Export the identity key encrypted with a password.
    /// Returns a base64-encoded blob that can be imported on another device.
    ///
    /// Uses PBKDF2-SHA256 (1M iterations) + AES-256-GCM.
    /// Blob v2 includes both DH and signing secrets.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the password is too short or encryption fails.
    #[wasm_bindgen(js_name = exportIdentity)]
    pub fn export_identity(&self, password: &str) -> Result<String, JsError> {
        let blob = export_identity_blob(
            &self.identity.dh_secret,
            &self.identity.sign_secret,
            password,
        )?;
        Ok(crypto::to_base64(&blob))
    }

    /// Import an identity key from an encrypted blob (from `exportIdentity`).
    /// Decrypts using the password and initializes a client with the recovered key.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the password is wrong, the blob is malformed,
    /// or server communication fails.
    #[wasm_bindgen(js_name = importIdentity)]
    pub async fn import_identity(
        user_id: &str,
        server_url: &str,
        blob_b64: &str,
        password: &str,
        auth_token: Option<String>,
    ) -> Result<Self, JsError> {
        let blob = crypto::from_base64(blob_b64)?;
        let (dh_secret, sign_secret) = import_identity_blob(&blob, password)?;

        let identity = IdentityKeyPair::from_secrets(*dh_secret, *sign_secret);
        let server_url = server_url.trim_end_matches('/').to_string();
        super::warn_http_with_token(&server_url, auth_token.as_deref());

        storage::save_identity_encrypted(
            user_id,
            &identity.dh_secret,
            &identity.sign_secret,
        )
        .await?;

        super::http::upload_public_keys(
            &server_url,
            user_id,
            &identity.dh_public,
            &identity.sign_public,
            auth_token.as_deref(),
        )
        .await?;

        Ok(Self {
            user_id: user_id.to_string(),
            server_url,
            auth_token,
            is_new: false,
            was_rotated: false,
            identity,
            key_cache: std::cell::RefCell::new(crate::key_directory::KeyCache::new()),
            gek_cache: std::cell::RefCell::new(crate::group::GekCache::new()),
        })
    }
}

// ---------- Identity export/import helpers ----------

/// Export blob: `version(2) || salt(16) || AES-GCM(dh_secret[32] || sign_secret[32])`
fn export_identity_blob(
    dh_secret: &[u8; 32],
    sign_secret: &[u8; 32],
    password: &str,
) -> Result<Vec<u8>, VeilError> {
    if password.len() < EXPORT_PASSWORD_MIN_LEN {
        return Err(VeilError::Validation(format!(
            "password must be at least {EXPORT_PASSWORD_MIN_LEN} characters"
        )));
    }

    let mut salt = [0u8; EXPORT_SALT_LEN];
    crypto::random_bytes(&mut salt)?;

    let wrapping_key = derive_export_key(password, &salt);

    let mut plaintext = Zeroizing::new([0u8; 64]);
    let (dh_half, sign_half) = plaintext.split_at_mut(32);
    dh_half.copy_from_slice(dh_secret);
    sign_half.copy_from_slice(sign_secret);

    let encrypted = crypto::aead_encrypt(&wrapping_key, &*plaintext, DOMAIN_EXPORT)?;

    let mut blob = Vec::with_capacity(
        1_usize
            .saturating_add(EXPORT_SALT_LEN)
            .saturating_add(encrypted.len()),
    );
    blob.push(2); // v2
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&encrypted);
    Ok(blob)
}

fn import_identity_blob(
    blob: &[u8],
    password: &str,
) -> Result<SecretPair, VeilError> {
    if blob.len() < EXPORT_BLOB_MIN_LEN {
        return Err(VeilError::Format(format!(
            "export blob too short: expected at least {EXPORT_BLOB_MIN_LEN} bytes, got {}",
            blob.len()
        )));
    }

    let version = blob.first()
        .ok_or_else(|| VeilError::Format("export blob too short".into()))?;

    if *version != 2 {
        return Err(VeilError::Format(format!("unsupported export version: {version}")));
    }

    let salt = blob.get(1..=EXPORT_SALT_LEN)
        .ok_or_else(|| VeilError::Format("export blob too short".into()))?;
    let encrypted = blob.get(1_usize.saturating_add(EXPORT_SALT_LEN)..)
        .ok_or_else(|| VeilError::Format("export blob too short".into()))?;

    let wrapping_key = derive_export_key(password, salt);
    let decrypted = crypto::aead_decrypt(&wrapping_key, encrypted, DOMAIN_EXPORT)?;

    if decrypted.len() != 64 {
        return Err(VeilError::Format(format!(
            "v2 export: expected 64 bytes, got {}",
            decrypted.len()
        )));
    }

    let (dh_half, sign_half) = decrypted.split_at(32);
    let mut dh = [0u8; 32];
    let mut sign = [0u8; 32];
    dh.copy_from_slice(dh_half);
    sign.copy_from_slice(sign_half);
    let result = (Zeroizing::new(dh), Zeroizing::new(sign));
    zeroize::Zeroize::zeroize(&mut dh);
    zeroize::Zeroize::zeroize(&mut sign);

    Ok(result)
}

fn derive_export_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(
        password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    const GOOD_PASSWORD: &str = "super-secret-backup-pw!!";

    fn make_secrets() -> ([u8; 32], [u8; 32]) {
        let (dh_secret, _) = crypto::generate_key_pair().unwrap();
        let (sign_secret, _) = crypto::generate_signing_key_pair().unwrap();
        (*dh_secret, *sign_secret)
    }

    // ---- Roundtrip ----

    #[test]
    fn export_import_roundtrip() {
        let (dh, sign) = make_secrets();
        let blob = export_identity_blob(&dh, &sign, GOOD_PASSWORD).unwrap();
        let (recovered_dh, recovered_sign) = import_identity_blob(&blob, GOOD_PASSWORD).unwrap();
        assert_eq!(*recovered_dh, dh);
        assert_eq!(*recovered_sign, sign);
    }

    // ---- Wrong password ----

    #[test]
    fn import_wrong_password_fails() {
        let (dh, sign) = make_secrets();
        let blob = export_identity_blob(&dh, &sign, GOOD_PASSWORD).unwrap();
        let result = import_identity_blob(&blob, "wrong-password-12345!!");
        assert!(matches!(result, Err(VeilError::Crypto(_))),
            "wrong password must fail decryption");
    }

    // ---- Short password rejected ----

    #[test]
    fn export_short_password_rejected() {
        let (dh, sign) = make_secrets();
        let result = export_identity_blob(&dh, &sign, "short");
        assert!(matches!(result, Err(VeilError::Validation(_))),
            "password shorter than 16 chars must be rejected");
    }

    #[test]
    fn export_exactly_min_password_accepted() {
        let (dh, sign) = make_secrets();
        let min_pw = "a".repeat(EXPORT_PASSWORD_MIN_LEN);
        let blob = export_identity_blob(&dh, &sign, &min_pw).unwrap();
        let (recovered_dh, _) = import_identity_blob(&blob, &min_pw).unwrap();
        assert_eq!(*recovered_dh, dh);
    }

    // ---- Truncated blob ----

    #[test]
    fn import_truncated_blob_rejected() {
        let (dh, sign) = make_secrets();
        let blob = export_identity_blob(&dh, &sign, GOOD_PASSWORD).unwrap();
        // Truncate to less than minimum
        let result = import_identity_blob(&blob[..EXPORT_BLOB_MIN_LEN - 1], GOOD_PASSWORD);
        assert!(matches!(result, Err(VeilError::Format(_))),
            "truncated blob must be rejected");
    }

    // ---- Unsupported version ----

    #[test]
    fn import_unsupported_version_rejected() {
        let (dh, sign) = make_secrets();
        let mut blob = export_identity_blob(&dh, &sign, GOOD_PASSWORD).unwrap();
        blob[0] = 99; // Set version to unsupported value
        let result = import_identity_blob(&blob, GOOD_PASSWORD);
        assert!(matches!(result, Err(VeilError::Format(_))),
            "unsupported version must be rejected");
    }

    // ---- Empty blob ----

    #[test]
    fn import_empty_blob_rejected() {
        let result = import_identity_blob(&[], GOOD_PASSWORD);
        assert!(matches!(result, Err(VeilError::Format(_))),
            "empty blob must be rejected");
    }

    // ---- Version byte preserved ----

    #[test]
    fn export_produces_v2_blob() {
        let (dh, sign) = make_secrets();
        let blob = export_identity_blob(&dh, &sign, GOOD_PASSWORD).unwrap();
        assert_eq!(blob[0], 2, "current export format must be version 2");
    }

    // ---- Different passwords produce different blobs ----

    #[test]
    fn different_passwords_produce_different_blobs() {
        let (dh, sign) = make_secrets();
        let blob1 = export_identity_blob(&dh, &sign, GOOD_PASSWORD).unwrap();
        let blob2 = export_identity_blob(&dh, &sign, "another-password-!!!!").unwrap();
        // Blobs differ due to different salt + different derived key
        assert_ne!(blob1, blob2);
    }

    // ---- Tampered blob fails ----

    #[test]
    fn import_tampered_blob_fails() {
        let (dh, sign) = make_secrets();
        let mut blob = export_identity_blob(&dh, &sign, GOOD_PASSWORD).unwrap();
        // Flip a bit in the encrypted portion
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let result = import_identity_blob(&blob, GOOD_PASSWORD);
        assert!(matches!(result, Err(VeilError::Crypto(_))),
            "tampered blob must fail authentication");
    }

    // ---- v1 import rejected ----

    #[test]
    fn import_v1_blob_rejected() {
        let (dh, _sign) = make_secrets();
        let password = GOOD_PASSWORD;

        // Build a v1 blob manually: version(1) || salt(16) || AES-GCM(dh_secret[32])
        let mut salt = [0u8; EXPORT_SALT_LEN];
        getrandom::getrandom(&mut salt).unwrap();
        let wrapping_key = derive_export_key(password, &salt);
        let encrypted = crypto::aead_encrypt(&wrapping_key, &dh, DOMAIN_EXPORT).unwrap();

        let mut blob = Vec::new();
        blob.push(1); // v1
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&encrypted);

        let result = import_identity_blob(&blob, password);
        assert!(matches!(result, Err(VeilError::Format(_))),
            "v1 blobs must be rejected");
    }
}
