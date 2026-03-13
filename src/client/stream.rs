use wasm_bindgen::prelude::*;

use crate::constants;
use crate::crypto::VeilError;
use crate::stream as veil_stream;

use super::VeilClient;

#[wasm_bindgen]
impl VeilClient {
    /// Initialize a streaming sealer for per-recipient encryption.
    /// Returns a `StreamSealer` that can encrypt chunks one at a time.
    /// Call `sealer.header()` to get the stream header JSON.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if a recipient's public key cannot be fetched
    /// or key wrapping fails.
    #[wasm_bindgen(js_name = sealStreamInit)]
    pub async fn seal_stream_init(
        &self,
        recipient_ids: Vec<JsValue>,
        metadata_json: Option<String>,
        chunk_size: Option<u32>,
    ) -> Result<StreamSealer, JsError> {
        let metadata = super::parse_metadata(metadata_json.as_deref())?;

        let keys = self.fetch_recipient_keys(&recipient_ids).await?;
        let recipient_refs: Vec<(&str, &[u8; 32])> =
            keys.iter().map(|(id, b)| (id.as_str(), &b.dh_public)).collect();

        let state = veil_stream::create_sealer(
            &self.user_id,
            &self.identity.sign_secret,
            &recipient_refs,
            &self.identity.dh_public,
            metadata,
            chunk_size,
        )?;

        Ok(StreamSealer { inner: state })
    }

    /// Initialize a streaming opener for per-recipient decryption.
    /// Verifies the header signature before unwrapping the DEK.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the header is unsigned, signature
    /// verification fails, the header is malformed, or the caller
    /// is not a recipient.
    #[wasm_bindgen(js_name = openStreamInit)]
    pub async fn open_stream_init(
        &self,
        header_json: &str,
    ) -> Result<StreamOpener, JsError> {
        let header: veil_stream::StreamHeader = serde_json::from_str(header_json)
            .map_err(|e| VeilError::Encoding(format!("parse stream header: {e}")))?;

        let signer_id = header
            .signer_id
            .as_ref()
            .ok_or_else(|| VeilError::Validation("stream header has no signer_id".into()))?;
        let _sig = header
            .signature
            .as_ref()
            .ok_or_else(|| VeilError::Validation("stream header has no signature".into()))?;

        let signer_keys = self.resolve_keys(signer_id).await?;
        veil_stream::verify_header(&header, &signer_keys.sign_public)?;

        let dek = veil_stream::unwrap_stream_dek(
            &header,
            &self.user_id,
            &self.identity.dh_secret,
            &self.identity.dh_public,
        )?;

        let state = veil_stream::create_opener(&header, dek)?;
        Ok(StreamOpener { inner: state })
    }

    /// Initialize a streaming opener **without** verifying the header
    /// signature.
    ///
    /// **Use with caution.** Intended for advanced scenarios where the
    /// caller has already verified the header or intentionally wants
    /// to skip verification (e.g. offline/cached streams).
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the header is malformed or the caller is
    /// not a recipient.
    #[wasm_bindgen(js_name = openStreamInitUnverified)]
    pub fn open_stream_init_unverified(
        &self,
        header_json: &str,
    ) -> Result<StreamOpener, JsError> {
        web_sys::console::warn_1(
            &"Veil: openStreamInitUnverified() called — header signature \
              verification skipped. Use openStreamInit() for verified decryption."
                .into(),
        );

        let header: veil_stream::StreamHeader = serde_json::from_str(header_json)
            .map_err(|e| VeilError::Encoding(format!("parse stream header: {e}")))?;

        let dek = veil_stream::unwrap_stream_dek(
            &header,
            &self.user_id,
            &self.identity.dh_secret,
            &self.identity.dh_public,
        )?;

        let state = veil_stream::create_opener(&header, dek)?;
        Ok(StreamOpener { inner: state })
    }

    /// Verify the Ed25519 signature on a stream header.
    /// Fetches the signer's public signing key from the server and
    /// TOFU-verifies it, then checks the header signature.
    ///
    /// Use this after `openStreamInit()` for direct streams that need
    /// signature verification.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the header is unsigned, missing `signer_id`,
    /// the signer's key cannot be fetched, or signature verification fails.
    #[wasm_bindgen(js_name = verifyStreamHeader)]
    pub async fn verify_stream_header(&self, header_json: &str) -> Result<(), JsError> {
        let header: veil_stream::StreamHeader = serde_json::from_str(header_json)
            .map_err(|e| VeilError::Encoding(format!("parse stream header: {e}")))?;

        let signer_id = header
            .signer_id
            .as_ref()
            .ok_or_else(|| VeilError::Validation("header has no signer_id".into()))?;

        let signer_keys = self.resolve_keys(signer_id).await?;
        veil_stream::verify_header(&header, &signer_keys.sign_public)?;
        Ok(())
    }

    /// Initialize a streaming sealer for group encryption.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the group bundle cannot be fetched or the
    /// caller is not a group member.
    #[wasm_bindgen(js_name = groupSealStreamInit)]
    pub async fn group_seal_stream_init(
        &self,
        group_id: &str,
        metadata_json: Option<String>,
        chunk_size: Option<u32>,
    ) -> Result<StreamSealer, JsError> {
        constants::validate_id(group_id, "group_id")?;
        let metadata = super::parse_metadata(metadata_json.as_deref())?;

        let bundle = self.fetch_group_bundle(group_id).await?;
        let gek = self.resolve_gek(&bundle)?;

        let state = veil_stream::create_group_sealer(
            &self.user_id,
            &self.identity.sign_secret,
            &gek,
            group_id,
            metadata,
            chunk_size,
        )?;

        Ok(StreamSealer { inner: state })
    }

    /// Initialize a streaming opener for group-encrypted streams.
    /// Fetches the group bundle to unwrap the GEK, then unwraps the DEK.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the header is malformed, the group bundle
    /// cannot be fetched, or the caller is not a group member.
    #[wasm_bindgen(js_name = groupOpenStreamInit)]
    pub async fn group_open_stream_init(
        &self,
        header_json: &str,
    ) -> Result<StreamOpener, JsError> {
        let header: veil_stream::StreamHeader = serde_json::from_str(header_json)
            .map_err(|e| VeilError::Encoding(format!("parse stream header: {e}")))?;

        // Require signature on group stream headers to prevent forgery via stripping
        let signer_id = header
            .signer_id
            .as_ref()
            .ok_or_else(|| VeilError::Validation("group stream header missing signer_id".into()))?;
        let _sig = header
            .signature
            .as_ref()
            .ok_or_else(|| VeilError::Validation("group stream header missing signature".into()))?;
        let signer_keys = self.resolve_keys(signer_id).await?;
        veil_stream::verify_header(&header, &signer_keys.sign_public)?;

        let group_id = header
            .group_id()
            .ok_or_else(|| VeilError::Validation("not a group stream".into()))?;

        let bundle = self.fetch_group_bundle(group_id).await?;
        let gek = self.resolve_gek(&bundle)?;

        let dek = veil_stream::unwrap_group_stream_dek(&header, &gek)?;
        let state = veil_stream::create_opener(&header, dek)?;
        Ok(StreamOpener { inner: state })
    }
}

// ---------- Streaming WASM types ----------

/// Streaming sealer for chunked encryption.
/// Call `sealChunk()` for each chunk, with `is_last = true` for the final one.
/// Call `header()` to get the stream header JSON.
/// Call `free()` when done to release WASM memory.
#[wasm_bindgen]
pub struct StreamSealer {
    inner: veil_stream::SealerState,
}

#[wasm_bindgen]
impl StreamSealer {
    /// Get the stream header as a JSON string.
    /// Contains the wrapped DEK, metadata, and signature.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if serialization fails.
    pub fn header(&self) -> Result<String, JsError> {
        serde_json::to_string(self.inner.header())
            .map_err(|e| JsError::new(&format!("serialize header: {e}")))
    }

    /// Encrypt a chunk. Set `is_last` to `true` for the final chunk.
    /// Returns the encrypted chunk as bytes.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the stream is finalized or encryption fails.
    #[wasm_bindgen(js_name = sealChunk)]
    pub fn seal_chunk(&mut self, chunk: &[u8], is_last: bool) -> Result<Vec<u8>, JsError> {
        self.inner
            .seal_chunk(chunk, is_last)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Streaming opener for chunked decryption.
/// Call `openChunk()` for each encrypted chunk.
/// Check `isDone()` after each chunk to detect the end of the stream.
/// Call `free()` when done to release WASM memory.
#[wasm_bindgen]
pub struct StreamOpener {
    inner: veil_stream::OpenerState,
}

#[wasm_bindgen]
impl StreamOpener {
    /// Decrypt a chunk. Returns the plaintext as bytes.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the stream is finished or decryption fails.
    #[wasm_bindgen(js_name = openChunk)]
    pub fn open_chunk(&mut self, encrypted_chunk: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .open_chunk(encrypted_chunk)
            .map(|z| z.to_vec())
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Whether the final chunk has been processed.
    #[wasm_bindgen(js_name = isDone)]
    // wasm_bindgen rejects const fn
    #[allow(clippy::missing_const_for_fn)]
    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }
}
