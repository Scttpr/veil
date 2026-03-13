use wasm_bindgen::prelude::*;

use crate::crypto::VeilError;

// ---------- Inline JS shim for IndexedDB + WebCrypto ----------

#[wasm_bindgen(inline_js = "
const DB_NAME = 'veil-keystore';
const STORE_NAME = 'wrapping-keys';
const KEY_ID = 'identity-wrapping-key';

function openDb() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME);
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

export async function idb_available() {
    try {
        if (typeof indexedDB === 'undefined' || !indexedDB) return false;
        const db = await openDb();
        db.close();
        return true;
    } catch (_) {
        return false;
    }
}

export async function generate_and_store_wrapping_key() {
    const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const req = store.add(key, KEY_ID);
        req.onsuccess = () => { db.close(); resolve(true); };
        req.onerror = (e) => {
            e.preventDefault();
            db.close();
            resolve(false);
        };
    });
}

export async function load_wrapping_key() {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(KEY_ID);
        req.onsuccess = () => { db.close(); resolve(req.result || null); };
        req.onerror = () => { db.close(); reject(req.error); };
    });
}

export async function webcrypto_encrypt(cryptoKey, plaintext, ad) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: ad },
        cryptoKey,
        plaintext
    );
    const result = new Uint8Array(12 + ct.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ct), 12);
    return result;
}

export async function webcrypto_decrypt(cryptoKey, data, ad) {
    const iv = data.slice(0, 12);
    const ct = data.slice(12);
    const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: ad },
        cryptoKey,
        ct
    );
    return new Uint8Array(pt);
}
")]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn idb_available() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn generate_and_store_wrapping_key() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn load_wrapping_key() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn webcrypto_encrypt(
        crypto_key: &JsValue,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn webcrypto_decrypt(
        crypto_key: &JsValue,
        data: &[u8],
        ad: &[u8],
    ) -> Result<JsValue, JsValue>;
}

// ---------- Rust wrappers ----------

/// Check if `IndexedDB` is available in the current browser context.
pub async fn is_idb_available() -> bool {
    idb_available()
        .await
        .map(|v| v.as_bool().unwrap_or(false))
        .unwrap_or(false)
}

/// Ensure a non-extractable AES-256-GCM wrapping key exists in `IndexedDB`.
/// If one already exists, returns it. Otherwise generates and stores a new one.
///
/// Uses `IndexedDB` `add()` (not `put()`) so that concurrent tabs cannot
/// overwrite each other's key — the first writer wins, and losers load
/// the winner's key.
pub async fn ensure_wrapping_key() -> Result<JsValue, VeilError> {
    let existing = load_wrapping_key()
        .await
        .map_err(|e| js_to_err("load_wrapping_key", &e))?;

    if !existing.is_null() && !existing.is_undefined() {
        return Ok(existing);
    }

    // add() returns false if the key already exists (another tab won the race).
    // Either way, the correct key is now in IndexedDB — just load it.
    generate_and_store_wrapping_key()
        .await
        .map_err(|e| js_to_err("generate_wrapping_key", &e))?;

    let key = load_wrapping_key()
        .await
        .map_err(|e| js_to_err("load_wrapping_key", &e))?;

    if key.is_null() || key.is_undefined() {
        return Err(VeilError::Storage(
            "wrapping key generation succeeded but key not found".into(),
        ));
    }

    Ok(key)
}

/// Encrypt `plaintext` with the `WebCrypto` `CryptoKey`.
/// Returns `nonce(12) || ciphertext(len) || tag(16)`.
///
/// `ad` is the full additional authenticated data string. The caller
/// is responsible for constructing it (e.g. `"veil-pin:alice"`).
pub async fn wrap_secret(
    crypto_key: &JsValue,
    plaintext: &[u8],
    ad: &str,
) -> Result<Vec<u8>, VeilError> {
    let result = webcrypto_encrypt(crypto_key, plaintext, ad.as_bytes())
        .await
        .map_err(|e| js_to_err("webcrypto_encrypt", &e))?;

    let arr = js_sys::Uint8Array::new(&result);
    Ok(arr.to_vec())
}

/// Decrypt `ciphertext` (`nonce || ct || tag`) with the `WebCrypto` `CryptoKey`.
///
/// `ad` must match the value used during encryption.
pub async fn unwrap_secret(
    crypto_key: &JsValue,
    ciphertext: &[u8],
    ad: &str,
) -> Result<Vec<u8>, VeilError> {
    let result = webcrypto_decrypt(crypto_key, ciphertext, ad.as_bytes())
        .await
        .map_err(|e| js_to_err("webcrypto_decrypt", &e))?;

    let arr = js_sys::Uint8Array::new(&result);
    Ok(arr.to_vec())
}

fn js_to_err(context: &str, err: &JsValue) -> VeilError {
    let msg = err
        .as_string()
        .unwrap_or_else(|| format!("{err:?}"));
    VeilError::Crypto(format!("{context}: {msg}"))
}
