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
    /// Id to pass as `after` for the next page. Absent when this page is complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<i64>,
}

/// JSON inbox upload: opaque envelope plus optional public trees.
/// Sending trees merges into the relay's canonical documents for those labels.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct InboxPush {
    /// Standard base64 of the exact `.kqpb` bytes.
    pub bytes: String,
    /// Public trees to merge. Omit or empty to leave server context unchanged.
    /// Nodes the sender does not hold stay on the relay.
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

/// HTTPS is always accepted. HTTP is only allowed for loopback hosts so a
/// bearer is never sent in the clear to a remote relay.
pub fn validate_relay_url(url: &str) -> Result<()> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        Error::RelayRequest("relay URL must use https, or http only to a loopback host".into())
    })?;
    let host = relay_host(rest);
    if host.is_empty() {
        return Err(Error::RelayRequest("relay URL is missing a host".into()));
    }
    match scheme {
        "https" => Ok(()),
        "http" if is_loopback_host(host) => Ok(()),
        "http" => Err(Error::RelayRequest(
            "HTTP relay URLs are only allowed for loopback hosts".into(),
        )),
        _ => Err(Error::RelayRequest(
            "relay URL must use https, or http only to a loopback host".into(),
        )),
    }
}

fn relay_host(rest: &str) -> &str {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = match authority.rsplit_once('@') {
        Some((_, hostport)) => hostport,
        None => authority,
    };
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority)
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

fn join_url(base: &str, path: &str) -> Result<String> {
    validate_relay_url(base)?;
    Ok(format!("{}{path}", base.trim_end_matches('/')))
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
    let resp = with_key(ureq::post(&join_url(base_url, "/inbox")?), api_key)
        .set("Content-Type", "application/octet-stream")
        .send_bytes(envelope);
    read_json(resp)
}

/// Upload an envelope and merge the sender's public-tree documents.
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
    let resp = with_key(ureq::post(&join_url(base_url, "/inbox")?), api_key)
        .set("Content-Type", "application/json")
        .send_string(&json);
    read_json(resp)
}

/// Fetch one page of envelopes for the pull key's bound fingerprint.
pub fn pull(
    base_url: &str,
    api_key: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<InboxList> {
    let mut params = Vec::new();
    if let Some(after) = after {
        params.push(format!("after={after}"));
    }
    if let Some(limit) = limit {
        params.push(format!("limit={limit}"));
    }
    let mut url = join_url(base_url, "/inbox")?;
    if !params.is_empty() {
        url.push('?');
        url.push_str(&params.join("&"));
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
    let resp = ureq::post(&join_url(base_url, "/keycheck")?)
        .set("Content-Type", "application/json")
        .send_string(&json);
    read_json(resp)
}

/// Replace the relay's canonical public tree (admin scope).
pub fn publish_tree(base_url: &str, api_key: &str, tree: &PublicTree) -> Result<PublicTree> {
    let body = serde_json::to_string(tree).map_err(|e| Error::RelayRequest(e.to_string()))?;
    let resp = with_key(ureq::put(&join_url(base_url, "/trees")?), api_key)
        .set("Content-Type", "application/json")
        .send_string(&body);
    read_json(resp)
}

/// Fetch the public-tree slice for this pull key's bound fingerprint.
pub fn fetch_tree_context(base_url: &str, api_key: &str, label: &str) -> Result<PublicTree> {
    let path = format!("/trees/{}/context", urlencoding_label(label));
    let resp = with_key(ureq::get(&join_url(base_url, &path)?), api_key).call();
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

#[cfg(test)]
mod url_tests {
    use super::*;

    #[test]
    fn rejects_remote_http_and_allows_loopback_and_https() {
        assert!(validate_relay_url("http://example.com:8787").is_err());
        assert!(validate_relay_url("http://192.168.1.10").is_err());
        assert!(validate_relay_url("ftp://127.0.0.1").is_err());
        validate_relay_url("http://127.0.0.1:8787").expect("loopback");
        validate_relay_url("http://localhost:8787").expect("localhost");
        validate_relay_url("http://[::1]:8787").expect("ipv6");
        validate_relay_url("https://relay.example.com").expect("https");
    }
}
