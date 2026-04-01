use std::cell::RefCell;

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::constants;
use crate::crypto::{self, VeilError};
use crate::group::{GekCache, GroupKeyBundle};
use crate::key_directory::{self, KeyCache, PublicKeyBundle};
use crate::keys::IdentityKeyPair;
use crate::storage;

mod audit;
mod direct;
mod group;
mod http;
mod identity;
mod stream;

pub use self::stream::{StreamOpener, StreamSealer};

/// Warn via console if the server URL uses plaintext HTTP while an auth token
/// is present. The token would be sent in the clear, visible to any network
/// observer.
fn warn_http_with_token(server_url: &str, auth_token: Option<&str>) {
    if auth_token.is_some() && server_url.starts_with("http://") {
        web_sys::console::warn_1(
            &"[Veil] Auth token is being sent over plaintext HTTP. \
              This exposes the token to network observers. \
              Use HTTPS in production."
                .into(),
        );
    }
}

/// Veil SDK client. Provides envelope encryption with multi-recipient
/// access control. All crypto runs client-side in WASM.
#[wasm_bindgen]
pub struct VeilClient {
    user_id: String,
    server_url: String,
    auth_token: Option<String>,
    is_new: bool,
    was_rotated: bool,
    identity: IdentityKeyPair,
    key_cache: RefCell<KeyCache>,
    gek_cache: RefCell<GekCache>,
}

#[wasm_bindgen]
impl VeilClient {
    /// Initialize the client. Generates or loads identity key.
    /// Uploads X25519 and Ed25519 public keys to the server.
    ///
    /// `auth_token` is an optional Bearer token included in all HTTP requests.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if key generation, storage access, or the server
    /// request fails.
    #[wasm_bindgen]
    pub async fn init(
        user_id: &str,
        server_url: &str,
        auth_token: Option<String>,
    ) -> Result<Self, JsError> {
        constants::validate_id(user_id, "user_id")?;
        let server_url = server_url.trim_end_matches('/').to_string();
        constants::validate_server_url(&server_url)?;
        constants::validate_auth_token(auth_token.as_deref())?;
        warn_http_with_token(&server_url, auth_token.as_deref());

        let (identity, is_new) =
            if let Some(keys) =
                storage::load_identity_encrypted(user_id).await?
            {
                (
                    IdentityKeyPair::from_secrets(*keys.dh_secret, *keys.sign_secret),
                    false,
                )
            } else {
                let ik = IdentityKeyPair::generate()?;
                storage::save_identity_encrypted(
                    user_id,
                    &ik.dh_secret,
                    &ik.sign_secret,
                )
                .await?;
                (ik, true)
            };

        // Only upload public keys for new identities. Existing identities
        // were already uploaded on creation; re-upload on every init wastes
        // a network round-trip. Use rotateKey() to push new keys.
        if is_new {
            http::upload_public_keys(
                &server_url,
                user_id,
                &identity.dh_public,
                &identity.sign_public,
                auth_token.as_deref(),
            )
            .await?;
        }

        Ok(Self {
            user_id: user_id.to_string(),
            server_url,
            auth_token,
            is_new,
            was_rotated: false,
            identity,
            key_cache: RefCell::new(KeyCache::new()),
            gek_cache: RefCell::new(GekCache::new()),
        })
    }

    /// Get our X25519 public key as base64.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> String {
        crypto::to_base64(&self.identity.dh_public)
    }

    /// Get our Ed25519 signing public key as base64.
    #[wasm_bindgen(js_name = signingKey)]
    pub fn signing_key(&self) -> String {
        crypto::to_base64(&self.identity.sign_public)
    }

    /// Get our user ID.
    #[wasm_bindgen(js_name = userId)]
    pub fn user_id(&self) -> String {
        self.user_id.clone()
    }

    /// Whether this client has a freshly generated identity key.
    /// If true, the app should prompt the user to call `exportIdentity()`
    /// so they can back up their key for use on other devices.
    #[wasm_bindgen(js_name = isNewIdentity)]
    // wasm_bindgen rejects const fn
    #[allow(clippy::missing_const_for_fn)]
    pub fn is_new_identity(&self) -> bool {
        self.is_new
    }

    /// Whether this client was created via key rotation (`rotateKey()`).
    /// If true, the app should notify recipients to call
    /// `trustKey(userId)` to accept the new keys, and `reseal()` any
    /// existing envelopes that should use the new identity.
    #[wasm_bindgen(js_name = wasRotated)]
    // wasm_bindgen rejects const fn
    #[allow(clippy::missing_const_for_fn)]
    pub fn was_rotated(&self) -> bool {
        self.was_rotated
    }

    /// Rotate the identity key pair (both X25519 and Ed25519).
    ///
    /// Generates new key pairs, saves them to storage (overwriting the old
    /// identity), and uploads the new public keys to the server.
    ///
    /// Returns a new `VeilClient` with the fresh keys. The old instance
    /// is stale and should be discarded.
    ///
    /// Recipients will see a TOFU mismatch and must call
    /// `trustKey(userId)` to accept the new keys. Re-wrapping existing
    /// envelopes is the caller's responsibility (use `reseal()`).
    ///
    /// # Errors
    ///
    /// Returns `JsError` if key generation, storage, or the server
    /// request fails.
    #[wasm_bindgen(js_name = rotateKey)]
    pub async fn rotate_key(
        user_id: &str,
        server_url: &str,
        auth_token: Option<String>,
    ) -> Result<Self, JsError> {
        constants::validate_id(user_id, "user_id")?;
        let server_url = server_url.trim_end_matches('/').to_string();
        constants::validate_server_url(&server_url)?;
        constants::validate_auth_token(auth_token.as_deref())?;
        warn_http_with_token(&server_url, auth_token.as_deref());

        let identity = IdentityKeyPair::generate()?;

        storage::save_identity_encrypted(
            user_id,
            &identity.dh_secret,
            &identity.sign_secret,
        )
        .await?;

        http::upload_public_keys(
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
            was_rotated: true,
            identity,
            key_cache: RefCell::new(KeyCache::new()),
            gek_cache: RefCell::new(GekCache::new()),
        })
    }
}

// ---------- Private helpers ----------

impl VeilClient {
    /// Fetch and cache a user's public key bundle.
    /// Uses the in-memory cache, falling back to server fetch + TOFU verify.
    async fn resolve_keys(&self, user_id: &str) -> Result<PublicKeyBundle, VeilError> {
        constants::validate_id(user_id, "user_id")?;
        if let Some(bundle) = self.key_cache.borrow_mut().get(user_id).cloned() {
            return Ok(bundle);
        }

        let bundle = http::fetch_public_keys(
            &self.server_url,
            user_id,
            self.auth_token.as_deref(),
        )
        .await?;
        key_directory::tofu_verify_and_pin(user_id, &bundle).await?;
        self.key_cache
            .borrow_mut()
            .insert(user_id.to_string(), bundle.clone());
        Ok(bundle)
    }

    /// Unwrap and cache a GEK from a group bundle.
    fn resolve_gek(
        &self,
        bundle: &GroupKeyBundle,
    ) -> Result<Zeroizing<[u8; 32]>, VeilError> {
        if let Some(gek) = self.gek_cache.borrow_mut().get(&bundle.group_id, bundle.epoch) {
            return Ok(gek.clone());
        }

        let gek = crate::group::unwrap_gek(
            bundle,
            &self.user_id,
            &self.identity.dh_secret,
            &self.identity.dh_public,
        )?;
        self.gek_cache.borrow_mut().insert(
            bundle.group_id.clone(),
            bundle.epoch,
            gek.clone(),
        );
        Ok(gek)
    }

    /// Update known signers to the current member list of a bundle
    /// we just created/modified locally.
    async fn update_known_signers_from_bundle(
        &self,
        bundle: &GroupKeyBundle,
    ) -> Result<(), VeilError> {
        let current_members: Vec<String> = bundle
            .members
            .iter()
            .map(|m| m.user_id.clone())
            .collect();
        storage::save_known_signers(&bundle.group_id, &current_members).await
    }

    /// Verify a group bundle's signature, enforce monotonic epochs, and
    /// validate the signer against the persisted set of known signers.
    ///
    /// On first contact with a group, the signer is accepted and recorded.
    /// On subsequent contacts, the signer must be in the known set or the
    /// bundle is rejected (prevents a compromised server from substituting
    /// a different group member as signer).
    async fn verify_and_accept_bundle(
        &self,
        bundle: &GroupKeyBundle,
    ) -> Result<(), VeilError> {
        let creator_keys = self.resolve_keys(&bundle.signer_id).await?;
        crate::group::verify_bundle(bundle, &creator_keys.sign_public)?;

        // Reject bundles with an epoch older than the last accepted one.
        // Same epoch is allowed (normal re-fetch); only downgrades are blocked.
        if let Some(last_epoch) = storage::load_group_epoch(&bundle.group_id).await? {
            if bundle.epoch < last_epoch {
                return Err(VeilError::Validation(format!(
                    "group '{}' bundle epoch {} is older than last-seen epoch {} \
                     (possible replay attack). Call invalidateGroupCache('{}') \
                     if this is expected.",
                    bundle.group_id, bundle.epoch, last_epoch, bundle.group_id
                )));
            }
        }

        // Enforce that the signer is a current member of the bundle.
        // This prevents a compromised former member from forging bundles.
        let signer_is_member = bundle
            .members
            .iter()
            .any(|m| m.user_id == bundle.signer_id);
        if !signer_is_member {
            return Err(VeilError::Validation(format!(
                "group '{}' bundle signed by '{}' who is not a current member \
                 of the bundle. A valid bundle must be signed by one of its members.",
                bundle.group_id, bundle.signer_id,
            )));
        }

        // On subsequent contacts, reject bundles signed by someone who was NOT
        // in the previously recorded member list. This detects server-side signer
        // substitution (e.g. a compromised server swapping in a colluding member).
        // Escape hatch: `invalidateGroupCache(groupId)` clears known signers.
        if let Some(known) = storage::load_known_signers(&bundle.group_id).await? {
            if !known.iter().any(|id| id == &bundle.signer_id) {
                return Err(VeilError::Validation(format!(
                    "group '{}' bundle signed by '{}' who was not in the previously \
                     known member set (possible server-side signer substitution). \
                     Call invalidateGroupCache('{}') if this is expected \
                     (e.g. after an out-of-band membership change).",
                    bundle.group_id, bundle.signer_id, bundle.group_id,
                )));
            }
        }

        // Record current members as the known-signer set for next verification.
        let current_members: Vec<String> = bundle
            .members
            .iter()
            .map(|m| m.user_id.clone())
            .collect();
        storage::save_known_signers(&bundle.group_id, &current_members).await?;

        storage::save_group_epoch(&bundle.group_id, bundle.epoch).await?;
        Ok(())
    }

    /// Parse a JS JSON value into a verified `GroupKeyBundle`.
    async fn parse_and_verify_bundle(
        &self,
        json_value: &JsValue,
    ) -> Result<GroupKeyBundle, VeilError> {
        let json_str = js_sys::JSON::stringify(json_value)
            .map_err(|e| http::js_err("JSON.stringify", &e))?
            .as_string()
            .ok_or_else(|| VeilError::Encoding("JSON.stringify returned non-string".into()))?;

        let bundle: GroupKeyBundle = serde_json::from_str(&json_str)
            .map_err(|e| VeilError::Encoding(format!("parse group bundle: {e}")))?;

        self.verify_and_accept_bundle(&bundle).await?;
        Ok(bundle)
    }

    /// Fetch a group bundle from the server and verify its signature.
    async fn fetch_group_bundle(
        &self,
        group_id: &str,
    ) -> Result<GroupKeyBundle, VeilError> {
        let url = format!(
            "{}/veil/groups/{}",
            self.server_url,
            http::encode_user_id(group_id),
        );
        let json_value = http::fetch_get_json(&url, self.auth_token.as_deref()).await?;
        self.parse_and_verify_bundle(&json_value).await
    }

    /// Try to fetch a group bundle; returns `None` on 404 (group not found).
    async fn try_fetch_group_bundle(
        &self,
        group_id: &str,
    ) -> Result<Option<GroupKeyBundle>, VeilError> {
        let url = format!(
            "{}/veil/groups/{}",
            self.server_url,
            http::encode_user_id(group_id),
        );

        match http::try_fetch_get_json(&url, self.auth_token.as_deref()).await? {
            Some(json_value) => self.parse_and_verify_bundle(&json_value).await.map(Some),
            None => Ok(None),
        }
    }

    async fn fetch_recipient_keys(
        &self,
        recipient_ids: &[JsValue],
    ) -> Result<Vec<(String, PublicKeyBundle)>, VeilError> {
        let mut seen = std::collections::HashSet::with_capacity(recipient_ids.len());
        let mut keys = Vec::with_capacity(recipient_ids.len());
        for id_val in recipient_ids {
            let id = id_val
                .as_string()
                .ok_or_else(|| VeilError::Validation("recipient ID must be a string".into()))?;
            if !seen.insert(id.clone()) {
                return Err(VeilError::Validation(format!("duplicate recipient ID: {id}")));
            }
            let bundle = self.resolve_keys(&id).await?;
            keys.push((id, bundle));
        }
        Ok(keys)
    }
}

fn parse_metadata(json: Option<&str>) -> Result<Option<serde_json::Value>, VeilError> {
    json.map_or(Ok(None), |s| {
        serde_json::from_str(s)
            .map(Some)
            .map_err(|e| VeilError::Encoding(format!("invalid metadata JSON: {e}")))
    })
}
