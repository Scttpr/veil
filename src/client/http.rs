use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, Response};

use crate::crypto::{self, VeilError};
use crate::key_directory::PublicKeyBundle;

pub fn encode_user_id(user_id: &str) -> String {
    String::from(js_sys::encode_uri_component(user_id))
}

pub async fn upload_public_keys(
    server_url: &str,
    user_id: &str,
    dh_public: &[u8; 32],
    sign_public: &[u8; 32],
    auth_token: Option<&str>,
) -> Result<(), VeilError> {
    let url = format!("{server_url}/veil/keys/{}", encode_user_id(user_id));
    let body = format!(
        r#"{{"publicKey":"{}","signingKey":"{}"}}"#,
        crypto::to_base64(dh_public),
        crypto::to_base64(sign_public),
    );
    fetch_put(&url, &body, auth_token).await
}

/// Fetch public keys from the server (no TOFU verification).
/// Returns a `PublicKeyBundle`.
pub async fn fetch_public_keys(
    server_url: &str,
    user_id: &str,
    auth_token: Option<&str>,
) -> Result<PublicKeyBundle, VeilError> {
    let url = format!("{server_url}/veil/keys/{}", encode_user_id(user_id));
    let json_value = fetch_get_json(&url, auth_token).await?;

    let pk_b64 = reflect_string(&json_value, "publicKey")?;
    let dh_public: [u8; 32] = crypto::from_base64(&pk_b64)?
        .try_into()
        .map_err(|_| VeilError::Format("publicKey not 32 bytes".into()))?;

    let sk_b64 = reflect_string(&json_value, "signingKey")?;
    let sign_public: [u8; 32] = crypto::from_base64(&sk_b64)?
        .try_into()
        .map_err(|_| VeilError::Format("signingKey not 32 bytes".into()))?;

    Ok(PublicKeyBundle { dh_public, sign_public })
}

pub async fn upload_group_bundle(
    server_url: &str,
    group_id: &str,
    bundle_json: &str,
    auth_token: Option<&str>,
) -> Result<(), VeilError> {
    let url = format!(
        "{server_url}/veil/groups/{}",
        encode_user_id(group_id),
    );
    fetch_put(&url, bundle_json, auth_token).await
}

// ---------- Low-level fetch helpers ----------

/// Call `globalThis.fetch(request)` — works in Window, Worker, and Node.js (v18+).
fn global_fetch(request: &Request) -> Result<js_sys::Promise, VeilError> {
    let global = js_sys::global();
    let fetch_fn = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|_| VeilError::Environment("globalThis.fetch not available".into()))?;
    if !fetch_fn.is_function() {
        return Err(VeilError::Environment(
            "globalThis.fetch is not a function (unsupported environment)".into(),
        ));
    }
    let promise = js_sys::Function::from(fetch_fn)
        .call1(&global, request)
        .map_err(|e| js_err("fetch", &e))?;
    Ok(js_sys::Promise::from(promise))
}

fn build_headers(auth_token: Option<&str>) -> Result<Headers, VeilError> {
    let headers = Headers::new().map_err(|e| js_err("Headers::new", &e))?;
    if let Some(token) = auth_token {
        if !token.is_empty() {
            headers
                .set("Authorization", &format!("Bearer {token}"))
                .map_err(|_| VeilError::Network("failed to set Authorization header".into()))?;
        }
    }
    Ok(headers)
}

async fn fetch_put(url: &str, body: &str, auth_token: Option<&str>) -> Result<(), VeilError> {
    let headers = build_headers(auth_token)?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| js_err("headers.set", &e))?;

    let opts = RequestInit::new();
    opts.set_method("PUT");
    opts.set_mode(RequestMode::Cors);
    opts.set_headers(&headers);
    opts.set_body(&JsValue::from_str(body));

    let request =
        Request::new_with_str_and_init(url, &opts).map_err(|e| js_err("Request::new", &e))?;

    let resp_value = JsFuture::from(global_fetch(&request)?)
        .await
        .map_err(|e| js_err("fetch PUT", &e))?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| VeilError::Network("not a Response".into()))?;

    if !resp.ok() {
        return Err(VeilError::Network(format!("PUT {} failed: {}", sanitize_url(url), resp.status())));
    }
    Ok(())
}

pub async fn fetch_get_json(url: &str, auth_token: Option<&str>) -> Result<JsValue, VeilError> {
    let headers = build_headers(auth_token)?;

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);
    opts.set_headers(&headers);

    let request =
        Request::new_with_str_and_init(url, &opts).map_err(|e| js_err("Request::new", &e))?;

    let resp_value = JsFuture::from(global_fetch(&request)?)
        .await
        .map_err(|e| js_err("fetch GET", &e))?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| VeilError::Network("not a Response".into()))?;

    if !resp.ok() {
        return Err(VeilError::Network(format!("GET {} failed: {}", sanitize_url(url), resp.status())));
    }

    JsFuture::from(resp.json().map_err(|e| js_err("response.json()", &e))?)
        .await
        .map_err(|e| js_err("json parse", &e))
}

/// Like `fetch_get_json` but returns `None` on 404 instead of an error.
pub async fn try_fetch_get_json(url: &str, auth_token: Option<&str>) -> Result<Option<JsValue>, VeilError> {
    let headers = build_headers(auth_token)?;

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);
    opts.set_headers(&headers);

    let request =
        Request::new_with_str_and_init(url, &opts).map_err(|e| js_err("Request::new", &e))?;

    let resp_value = JsFuture::from(global_fetch(&request)?)
        .await
        .map_err(|e| js_err("fetch GET", &e))?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| VeilError::Network("not a Response".into()))?;

    if resp.status() == 404 {
        return Ok(None);
    }

    if !resp.ok() {
        return Err(VeilError::Network(format!("GET {} failed: {}", sanitize_url(url), resp.status())));
    }

    let json = JsFuture::from(resp.json().map_err(|e| js_err("response.json()", &e))?)
        .await
        .map_err(|e| js_err("json parse", &e))?;
    Ok(Some(json))
}

fn reflect_string(obj: &JsValue, key: &str) -> Result<String, VeilError> {
    js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .map_err(|e| js_err(&format!("reflect {key}"), &e))?
        .as_string()
        .ok_or_else(|| VeilError::Format(format!("{key} is not a string")))
}

/// Redact URL to only the endpoint path segment (keys/groups),
/// stripping the server origin and any user/group IDs.
fn sanitize_url(url: &str) -> String {
    let Some(idx) = url.find("/veil/") else {
        return "<redacted-url>".into();
    };
    let path = &url[idx..];
    // Keep the endpoint type (/veil/keys, /veil/groups), redact user/group IDs
    let parts: Vec<_> = path.splitn(4, '/').collect();
    match (parts.first(), parts.get(1), parts.get(2)) {
        (Some(a), Some(b), Some(c)) => format!("{a}/{b}/{c}/<id>"),
        _ => path.to_string(),
    }
}

pub fn js_err(context: &str, err: &JsValue) -> VeilError {
    let msg = err
        .as_string()
        .unwrap_or_else(|| format!("{err:?}"));
    VeilError::Network(format!("{context}: {msg}"))
}
