use zeroize::Zeroizing;

use crate::crypto;

/// Long-term identity key pair: X25519 (encryption) + Ed25519 (signing).
/// Secret keys are zeroized on drop.
pub struct IdentityKeyPair {
    pub dh_secret: Zeroizing<[u8; 32]>,
    pub dh_public: [u8; 32],
    pub sign_secret: Zeroizing<[u8; 32]>,
    pub sign_public: [u8; 32],
}

impl IdentityKeyPair {
    /// Generate a new identity key pair (X25519 + Ed25519).
    ///
    /// # Errors
    ///
    /// Returns `VeilError` if the system RNG fails.
    pub fn generate() -> Result<Self, crypto::VeilError> {
        let (dh_secret, dh_public) = crypto::generate_key_pair()?;
        let (sign_secret, sign_public) = crypto::generate_signing_key_pair()?;
        Ok(Self { dh_secret, dh_public, sign_secret, sign_public })
    }

    pub fn from_secrets(mut dh_secret_bytes: [u8; 32], mut sign_secret_bytes: [u8; 32]) -> Self {
        use x25519_dalek::{PublicKey, StaticSecret};
        use zeroize::Zeroize as _;

        let static_secret = StaticSecret::from(dh_secret_bytes);
        let dh_public = PublicKey::from(&static_secret).to_bytes();
        // Store clamped bytes so exports are consistent with generate()
        let dh_secret = Zeroizing::new(static_secret.to_bytes());
        // StaticSecret: ZeroizeOnDrop — zeroized here
        drop(static_secret);

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&sign_secret_bytes);
        let sign_public = signing_key.verifying_key().to_bytes();
        drop(signing_key); // ZeroizeOnDrop — zeroized here

        let result = Self {
            dh_secret,
            dh_public,
            sign_secret: Zeroizing::new(sign_secret_bytes),
            sign_public,
        };

        dh_secret_bytes.zeroize();
        sign_secret_bytes.zeroize();
        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn generate_produces_nonzero_keys() {
        let kp = IdentityKeyPair::generate().unwrap();
        assert_ne!(kp.dh_public, [0u8; 32]);
        assert_ne!(kp.sign_public, [0u8; 32]);
    }

    #[test]
    fn two_generates_produce_different_keys() {
        let kp1 = IdentityKeyPair::generate().unwrap();
        let kp2 = IdentityKeyPair::generate().unwrap();
        assert_ne!(kp1.dh_public, kp2.dh_public);
        assert_ne!(kp1.sign_public, kp2.sign_public);
    }

    #[test]
    fn from_secrets_reproduces_public_keys() {
        let kp = IdentityKeyPair::generate().unwrap();
        let restored = IdentityKeyPair::from_secrets(*kp.dh_secret, *kp.sign_secret);
        assert_eq!(restored.dh_public, kp.dh_public);
        assert_eq!(restored.sign_public, kp.sign_public);
    }

    #[test]
    fn from_secrets_dh_bytes_consistent_with_generate() {
        // Ensure from_secrets stores the same DH secret bytes as generate,
        // so that export → import roundtrips produce identical key material.
        let kp = IdentityKeyPair::generate().unwrap();
        let restored = IdentityKeyPair::from_secrets(*kp.dh_secret, *kp.sign_secret);
        assert_eq!(*restored.dh_secret, *kp.dh_secret);
        assert_eq!(*restored.sign_secret, *kp.sign_secret);
    }

    #[test]
    fn from_secrets_signing_roundtrip() {
        // Verify a signature made with from_secrets keys can be verified
        // with the derived public key.
        let kp = IdentityKeyPair::generate().unwrap();
        let restored = IdentityKeyPair::from_secrets(*kp.dh_secret, *kp.sign_secret);
        let msg = b"test message";
        let sig = crypto::ed25519_sign(&restored.sign_secret, msg);
        assert!(crypto::ed25519_verify(&restored.sign_public, msg, &sig).is_ok());
        // Cross-verify with original public key
        assert!(crypto::ed25519_verify(&kp.sign_public, msg, &sig).is_ok());
    }

    #[test]
    fn from_secrets_dh_roundtrip() {
        // Verify DH with from_secrets keys produces the same shared secret.
        let kp1 = IdentityKeyPair::generate().unwrap();
        let kp2 = IdentityKeyPair::generate().unwrap();
        let restored1 = IdentityKeyPair::from_secrets(*kp1.dh_secret, *kp1.sign_secret);

        let shared_original = crypto::dh(&kp1.dh_secret, &kp2.dh_public).unwrap();
        let shared_restored = crypto::dh(&restored1.dh_secret, &kp2.dh_public).unwrap();
        assert_eq!(*shared_original, *shared_restored);
    }
}
