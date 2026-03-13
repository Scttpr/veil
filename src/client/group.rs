use wasm_bindgen::prelude::*;

use crate::constants;
use crate::crypto::VeilError;
use crate::envelope::{self, Envelope};
use crate::storage;

use super::VeilClient;

#[wasm_bindgen]
impl VeilClient {
    /// Create a new group. Generates a GEK, wraps it for each member,
    /// and uploads the bundle to the server.
    /// Returns the `GroupKeyBundle` as a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if a member's public key cannot be fetched,
    /// key generation fails, or the server request fails.
    #[wasm_bindgen(js_name = createGroup)]
    pub async fn create_group(
        &self,
        group_id: &str,
        member_ids: Vec<JsValue>,
    ) -> Result<String, JsError> {
        constants::validate_id(group_id, "group_id")?;
        // Fetch all member keys (including self)
        let mut all_keys: Vec<(String, [u8; 32])> =
            Vec::with_capacity(1_usize.saturating_add(member_ids.len()));
        all_keys.push((self.user_id.clone(), self.identity.dh_public));

        let fetched = self.fetch_recipient_keys(&member_ids).await?;
        for (id, bundle) in fetched {
            if id == self.user_id {
                continue; // already added above
            }
            all_keys.push((id, bundle.dh_public));
        }

        let member_refs: Vec<(&str, &[u8; 32])> =
            all_keys.iter().map(|(id, k)| (id.as_str(), k)).collect();

        let (bundle, gek) = crate::group::create_bundle(
            group_id,
            1,
            &self.user_id,
            &self.identity.sign_secret,
            &member_refs,
        )?;

        let bundle_json = serde_json::to_string(&bundle)
            .map_err(|e| JsError::new(&format!("serialize: {e}")))?;

        super::http::upload_group_bundle(
            &self.server_url,
            group_id,
            &bundle_json,
            self.auth_token.as_deref(),
        )
        .await?;

        // Persist known signers; epoch saved on first fetch via verify_and_accept_bundle.
        storage::save_known_signers(group_id, std::slice::from_ref(&self.user_id)).await?;

        // Cache GEK so groupSeal can use it without re-unwrapping.
        self.gek_cache.borrow_mut().insert(
            group_id.to_string(),
            1,
            gek,
        );

        Ok(bundle_json)
    }

    /// Add a member to a group. Fetches the bundle, unwraps the GEK,
    /// wraps for the new member, and uploads the updated bundle.
    /// Returns the updated `GroupKeyBundle` as a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the caller is not a member, the new member's
    /// key cannot be fetched, or the server request fails.
    #[wasm_bindgen(js_name = addGroupMember)]
    pub async fn add_group_member(
        &self,
        group_id: &str,
        member_id: &str,
    ) -> Result<String, JsError> {
        constants::validate_id(group_id, "group_id")?;
        let bundle = self.fetch_group_bundle(group_id).await?;

        let member_keys = self.resolve_keys(member_id).await?;

        let updated = crate::group::add_member(
            &bundle,
            &self.user_id,
            &self.identity.dh_secret,
            &self.identity.dh_public,
            &self.identity.sign_secret,
            member_id,
            &member_keys.dh_public,
        )?;

        let bundle_json = serde_json::to_string(&updated)
            .map_err(|e| JsError::new(&format!("serialize: {e}")))?;

        super::http::upload_group_bundle(
            &self.server_url,
            group_id,
            &bundle_json,
            self.auth_token.as_deref(),
        )
        .await?;

        // Update known signers to the current member list
        self.update_known_signers_from_bundle(&updated).await?;

        Ok(bundle_json)
    }

    /// Remove a member from a group (rotates the GEK).
    /// Generates a new GEK, wraps for remaining members, uploads.
    /// Returns the updated `GroupKeyBundle` as a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the member is not found, remaining members'
    /// keys cannot be fetched, or the server request fails.
    #[wasm_bindgen(js_name = removeGroupMember)]
    pub async fn remove_group_member(
        &self,
        group_id: &str,
        member_id: &str,
    ) -> Result<String, JsError> {
        constants::validate_id(group_id, "group_id")?;
        let bundle = self.fetch_group_bundle(group_id).await?;

        // Collect remaining member IDs (excluding removed member)
        let remaining_ids: Vec<String> = bundle
            .members
            .iter()
            .map(|w| w.user_id.clone())
            .filter(|id| id != member_id)
            .collect();

        // Fetch public keys for remaining members (except self)
        let mut all_keys: Vec<(String, [u8; 32])> = Vec::with_capacity(remaining_ids.len());
        for id in &remaining_ids {
            if id == &self.user_id {
                all_keys.push((self.user_id.clone(), self.identity.dh_public));
            } else {
                let member_keys = self.resolve_keys(id).await?;
                all_keys.push((id.clone(), member_keys.dh_public));
            }
        }

        let member_refs: Vec<(&str, &[u8; 32])> =
            all_keys.iter().map(|(id, k)| (id.as_str(), k)).collect();

        let (updated, new_gek) = crate::group::remove_member(
            &bundle,
            &self.user_id,
            &self.identity.sign_secret,
            member_id,
            &member_refs,
        )?;

        // Cache the new GEK (old one is invalidated by epoch bump)
        self.gek_cache.borrow_mut().insert(
            group_id.to_string(),
            updated.epoch,
            new_gek,
        );

        let bundle_json = serde_json::to_string(&updated)
            .map_err(|e| JsError::new(&format!("serialize: {e}")))?;

        super::http::upload_group_bundle(
            &self.server_url,
            group_id,
            &bundle_json,
            self.auth_token.as_deref(),
        )
        .await?;

        // Update known signers to the current member list
        self.update_known_signers_from_bundle(&updated).await?;

        Ok(bundle_json)
    }

    /// Seal data for a group. Fetches the group bundle, unwraps the GEK,
    /// and seals an envelope using the group key.
    /// Returns the Envelope as a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the caller is not a group member, the bundle
    /// cannot be fetched, or encryption fails.
    #[wasm_bindgen(js_name = groupSeal)]
    pub async fn group_seal(
        &self,
        plaintext: &str,
        group_id: &str,
        metadata_json: Option<String>,
    ) -> Result<String, JsError> {
        constants::validate_id(group_id, "group_id")?;
        let metadata = super::parse_metadata(metadata_json.as_deref())?;

        let bundle = self.fetch_group_bundle(group_id).await?;
        let gek = self.resolve_gek(&bundle)?;

        let env = crate::group::seal(
            plaintext.as_bytes(),
            &gek,
            group_id,
            &self.user_id,
            &self.identity.sign_secret,
            metadata,
        )?;

        serde_json::to_string(&env).map_err(|e| JsError::new(&format!("serialize: {e}")))
    }

    /// Open a group envelope. Fetches the group bundle, unwraps the GEK,
    /// and decrypts the envelope.
    /// Returns the plaintext as a string.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the envelope is not a group envelope, the
    /// caller is not a group member, or decryption fails.
    #[wasm_bindgen(js_name = groupOpen)]
    pub async fn group_open(&self, envelope_json: &str) -> Result<String, JsError> {
        let env: Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;

        let group_id = env
            .group_id()
            .ok_or_else(|| VeilError::Validation("not a group envelope".into()))?;

        // Require signature on group envelopes to prevent forgery via signature stripping
        let signer_id = env
            .signer_id
            .as_ref()
            .ok_or_else(|| VeilError::Validation("group envelope missing signer_id".into()))?;
        let _sig = env
            .signature
            .as_ref()
            .ok_or_else(|| VeilError::Validation("group envelope missing signature".into()))?;
        let signer_keys = self.resolve_keys(signer_id).await?;
        envelope::verify(&env, &signer_keys.sign_public)?;

        let bundle = self.fetch_group_bundle(group_id).await?;
        let gek = self.resolve_gek(&bundle)?;

        let pt = crate::group::open(&env, &gek)?;
        String::from_utf8(pt.to_vec()).map_err(|e| JsError::new(&format!("invalid utf8: {e}")))
    }

    // ---------- Auto-group (PQ-ready path) ----------

    /// Seal data using an auto-managed group.
    ///
    /// Computes a deterministic group ID from the participants, creates
    /// the group if it doesn't exist, and seals using the group key.
    /// This amortizes the per-recipient key wrapping cost: only one
    /// symmetric DEK wrap per message, regardless of recipient count.
    ///
    /// When PQ key exchange is added, only group creation/membership
    /// changes incur the expensive KEM operations — message encryption
    /// stays purely symmetric.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if a recipient's key cannot be fetched,
    /// group creation fails, or encryption fails.
    #[wasm_bindgen(js_name = autoSeal)]
    pub async fn auto_seal(
        &self,
        plaintext: &str,
        recipient_ids: Vec<JsValue>,
        metadata_json: Option<String>,
    ) -> Result<String, JsError> {
        let metadata = super::parse_metadata(metadata_json.as_deref())?;

        // Build deduplicated list of all participant IDs
        let mut seen = std::collections::HashSet::with_capacity(
            1_usize.saturating_add(recipient_ids.len()),
        );
        let mut all_ids: Vec<String> =
            Vec::with_capacity(1_usize.saturating_add(recipient_ids.len()));
        all_ids.push(self.user_id.clone());
        seen.insert(self.user_id.clone());
        for id_val in &recipient_ids {
            let id = id_val
                .as_string()
                .ok_or_else(|| VeilError::Validation("recipient ID must be a string".into()))?;
            if seen.insert(id.clone()) {
                all_ids.push(id);
            }
        }
        let all_refs: Vec<&str> = all_ids.iter().map(String::as_str).collect();
        let group_id = crate::group::auto_group_id(&all_refs);

        // Try to use existing group, or create one
        let gek = if let Some(bundle) = self.try_fetch_group_bundle(&group_id).await? {
            self.resolve_gek(&bundle)?
        } else {
            let keys = self.fetch_recipient_keys(&recipient_ids).await?;
            let mut member_keys: Vec<(String, [u8; 32])> =
                Vec::with_capacity(1_usize.saturating_add(keys.len()));
            member_keys.push((self.user_id.clone(), self.identity.dh_public));
            for (id, bundle) in &keys {
                if *id != self.user_id {
                    member_keys.push((id.clone(), bundle.dh_public));
                }
            }
            let member_refs: Vec<(&str, &[u8; 32])> = member_keys
                .iter()
                .map(|(id, k)| (id.as_str(), k))
                .collect();

            let (bundle, gek) = crate::group::create_bundle(
                &group_id,
                1,
                &self.user_id,
                &self.identity.sign_secret,
                &member_refs,
            )?;

            let bundle_json = serde_json::to_string(&bundle)
                .map_err(|e| JsError::new(&format!("serialize: {e}")))?;
            super::http::upload_group_bundle(
                &self.server_url,
                &group_id,
                &bundle_json,
                self.auth_token.as_deref(),
            )
            .await?;

            storage::save_known_signers(&group_id, std::slice::from_ref(&self.user_id)).await?;

            self.gek_cache.borrow_mut().insert(
                group_id.clone(),
                bundle.epoch,
                gek.clone(),
            );
            gek
        };

        let env = crate::group::seal(
            plaintext.as_bytes(),
            &gek,
            &group_id,
            &self.user_id,
            &self.identity.sign_secret,
            metadata,
        )?;

        serde_json::to_string(&env).map_err(|e| JsError::new(&format!("serialize: {e}")))
    }

    /// Open any envelope (direct or group) transparently.
    ///
    /// Detects the envelope type and dispatches to the correct open path.
    /// Verifies signatures when present. For group envelopes, fetches
    /// the bundle and uses the GEK cache.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the envelope is malformed, signature
    /// verification fails, or decryption fails.
    #[wasm_bindgen(js_name = autoOpen)]
    pub async fn auto_open(&self, envelope_json: &str) -> Result<String, JsError> {
        let env: Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;

        // Require signature to prevent forgery via signature stripping
        let signer_id = env
            .signer_id
            .as_ref()
            .ok_or_else(|| VeilError::Validation("envelope missing signer_id".into()))?;
        let _sig = env
            .signature
            .as_ref()
            .ok_or_else(|| VeilError::Validation("envelope missing signature".into()))?;
        let signer_keys = self.resolve_keys(signer_id).await?;
        envelope::verify(&env, &signer_keys.sign_public)?;

        let pt = if env.is_group() {
            let group_id = env
                .group_id()
                .ok_or_else(|| VeilError::Validation("not a group envelope".into()))?;
            let bundle = self.fetch_group_bundle(group_id).await?;
            let gek = self.resolve_gek(&bundle)?;
            crate::group::open(&env, &gek)?.to_vec()
        } else {
            envelope::open(
                &env,
                &self.user_id,
                &self.identity.dh_secret,
                &self.identity.dh_public,
            )?.to_vec()
        };

        String::from_utf8(pt).map_err(|e| JsError::new(&format!("invalid utf8: {e}")))
    }

    /// Invalidate the cached GEK for a group (e.g. after external
    /// membership changes). The next group operation will re-fetch
    /// the bundle from the server. Also clears the persisted epoch
    /// floor and known signers, allowing acceptance of any bundle.
    #[wasm_bindgen(js_name = invalidateGroupCache)]
    pub fn invalidate_group_cache(&self, group_id: &str) {
        self.gek_cache.borrow_mut().invalidate(group_id);
        let _ = storage::clear_group_epoch(group_id);
        let _ = storage::clear_known_signers(group_id);
    }

    /// Clear all in-memory caches (key directory + GEK).
    /// Useful after key rotation or security-sensitive operations.
    #[wasm_bindgen(js_name = clearCaches)]
    pub fn clear_caches(&self) {
        self.key_cache.borrow_mut().clear();
        self.gek_cache.borrow_mut().clear();
    }
}
