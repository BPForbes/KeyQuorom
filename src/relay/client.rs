//! HTTP JSON wire types and a synchronous `ureq` client for the relay.

use crate::error::{Error, Result};
use crate::key_tree::PublicTree;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct InboxAccepted {
    pub id: i64,
    pub recipient_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct InboxEnvelope {
    pub id: i64,
    pub recipient_fingerprint: String,
    /// Standard base64 of the exact `.kqpb` bytes.
    pub bytes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct InboxList {
    pub envelopes: Vec<InboxEnvelope>,
    /// Visible public-tree slices for this pull key's fingerprint.
    /// Empty when nothing is published or this fingerprint is not in a tree.
    #[serde(default)]
    pub trees: Vec<PublicTree>,
}

/// JSON inbox upload: opaque envelope plus optional full public trees.
/// Sending trees replaces the relay's canonical documents for those labels.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct InboxPush {
    /// Standard base64 of the exact `.kqpb` bytes.
    pub bytes: String,
    /// Full public trees (not slices). Omit or empty to leave server context unchanged.
    #[serde(default)]
    pub trees: Vec<PublicTree>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    pub error: String,
}

/// Body for the unauthenticated `POST /keycheck` route.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct KeyCheckRequest {
    /// Raw `kq_…` bearer. Used by `loadkey` and `--api-key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// `hex(SHA-256(raw))` stored on the personal instance after a valid load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_hash: Option<String>,
}

/// Whether the key is live on the service. Invalid keys are not distinguished
/// (unknown, expired, and revoked all return `valid: false`).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct KeyCheckResponse {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_fingerprint: Option<String>,
}

fn join_url(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

fn with_key(req: ureq::Request, api_key: &str) -> ureq::Request {
    req.set("Authorization", &format!("Bearer {api_key}"))
}

fn read_json<T: serde::de::DeserializeOwned>(
    result: std::result::Result<ureq::Response, ureq::Error>,
) -> Result<T> {
    match result {
        Ok(resp) => {
            let body = resp
                .into_string()
                .map_err(|e| Error::RelayRequest(e.to_string()))?;
            serde_json::from_str(&body).map_err(|e| Error::RelayRequest(e.to_string()))
        }
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            Err(Error::RelayRequest(format!("HTTP {code}: {body}")))
        }
        Err(e) => Err(Error::RelayRequest(e.to_string())),
    }
}

/// Upload one opaque `.kqpb` envelope (no tree update).
pub fn push(base_url: &str, api_key: &str, envelope: &[u8]) -> Result<InboxAccepted> {
    let resp = with_key(ureq::post(&join_url(base_url, "/inbox")), api_key)
        .set("Content-Type", "application/octet-stream")
        .send_bytes(envelope);
    read_json(resp)
}

/// Upload an envelope and replace the relay's full public-tree documents.
pub fn push_with_trees(
    base_url: &str,
    api_key: &str,
    envelope: &[u8],
    trees: &[PublicTree],
) -> Result<InboxAccepted> {
    let body = InboxPush {
        bytes: base64::engine::general_purpose::STANDARD.encode(envelope),
        trees: trees.to_vec(),
    };
    let json = serde_json::to_string(&body).map_err(|e| Error::RelayRequest(e.to_string()))?;
    let resp = with_key(ureq::post(&join_url(base_url, "/inbox")), api_key)
        .set("Content-Type", "application/json")
        .send_string(&json);
    read_json(resp)
}

/// Fetch envelopes for the pull key's bound fingerprint.
pub fn pull(base_url: &str, api_key: &str, after: Option<i64>) -> Result<InboxList> {
    let mut url = join_url(base_url, "/inbox");
    if let Some(after) = after {
        url.push_str(&format!("?after={after}"));
    }
    let resp = with_key(ureq::get(&url), api_key).call();
    read_json(resp)
}

/// Ask the relay whether a bearer is live. No `Authorization` header.
pub fn check_key(base_url: &str, token: &str) -> Result<KeyCheckResponse> {
    post_keycheck(
        base_url,
        &KeyCheckRequest {
            token: Some(token.to_string()),
            key_hash: None,
        },
    )
}

/// Revalidate a hash stored on the personal instance. No `Authorization` header.
pub fn check_key_hash(base_url: &str, key_hash: &str) -> Result<KeyCheckResponse> {
    post_keycheck(
        base_url,
        &KeyCheckRequest {
            token: None,
            key_hash: Some(key_hash.to_string()),
        },
    )
}

fn post_keycheck(base_url: &str, body: &KeyCheckRequest) -> Result<KeyCheckResponse> {
    let json = serde_json::to_string(body).map_err(|e| Error::RelayRequest(e.to_string()))?;
    let resp = ureq::post(&join_url(base_url, "/keycheck"))
        .set("Content-Type", "application/json")
        .send_string(&json);
    read_json(resp)
}

/// Replace the relay's canonical public tree (admin scope).
pub fn publish_tree(base_url: &str, api_key: &str, tree: &PublicTree) -> Result<PublicTree> {
    let body = serde_json::to_string(tree).map_err(|e| Error::RelayRequest(e.to_string()))?;
    let resp = with_key(ureq::put(&join_url(base_url, "/trees")), api_key)
        .set("Content-Type", "application/json")
        .send_string(&body);
    read_json(resp)
}

/// Fetch the public-tree slice for this pull key's bound fingerprint.
pub fn fetch_tree_context(base_url: &str, api_key: &str, label: &str) -> Result<PublicTree> {
    let path = format!("/trees/{}/context", urlencoding_label(label));
    let resp = with_key(ureq::get(&join_url(base_url, &path)), api_key).call();
    read_json(resp)
}

fn urlencoding_label(label: &str) -> String {
    let mut out = String::new();
    for b in label.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}
