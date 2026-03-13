#![allow(clippy::unwrap_used, clippy::missing_panics_doc, clippy::type_complexity)]

use zeroize::Zeroizing;

use crate::crypto;

/// Returns `(id, dh_secret, dh_public, sign_secret, sign_public)`.
pub fn make_user() -> (String, Zeroizing<[u8; 32]>, [u8; 32], Zeroizing<[u8; 32]>, [u8; 32]) {
    let (dh_secret, dh_public) = crypto::generate_key_pair().unwrap();
    let (sign_secret, sign_public) = crypto::generate_signing_key_pair().unwrap();
    let id = crypto::to_base64(&dh_public[..8]);
    (id, dh_secret, dh_public, sign_secret, sign_public)
}
