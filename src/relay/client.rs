//! HTTP JSON wire types and a synchronous `ureq` client for the relay.

use super::register::{RegisterRequest, RegisterResponse};
use crate::error::{Error, Result};
use crate::key_tree::PublicTree;
use crate::provider::{self, Certificate};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::Duration;
use url::Url;
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
    /// UTC expiry as `YYYY-MM-DD HH:MM:00`. After this instant the host
    /// scan and inbox pull delete the envelope so it cannot be fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[cfg_attr(not(feature = "provider"), allow(dead_code))]
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

/// Unauthenticated `POST /provider-identity` challenge.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ProviderIdentityRequest {
    /// Standard base64 of a 32-byte random challenge.
    pub challenge: String,
}

/// Certificate bytes plus the relay signature over the challenge.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ProviderIdentityResponse {
    /// Standard base64 of the `provider.kqcert` bytes.
    pub certificate: String,
    /// Standard base64 of the 64-byte Ed25519 signature.
    pub signature: String,
}

/// HTTPS is always accepted. HTTP is only allowed for loopback hosts so a
/// bearer is never sent in the clear to a remote relay.
pub fn validate_relay_url(url: &str) -> Result<()> {
    parse_relay_url(url).map(|_| ())
}

/// Parse once with the same WHATWG parser `ureq` uses, then validate that
/// parsed host. Callers must reuse the returned `Url` for the request so a
/// string-level host check cannot disagree with the connect target.
fn parse_relay_url(raw: &str) -> Result<Url> {
    let raw = raw.trim();
    if raw.contains('\\') {
        return Err(Error::RelayRequest(
            "relay URL must not contain backslashes".into(),
        ));
    }
    let parsed = Url::parse(raw).map_err(|_| {
        Error::RelayRequest("relay URL must use https, or http only to a loopback host".into())
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::RelayRequest(
            "relay URL must not include userinfo".into(),
        ));
    }
    if parsed.host().is_none() {
        return Err(Error::RelayRequest("relay URL is missing a host".into()));
    }
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if is_loopback_url(&parsed) => Ok(parsed),
        "http" => Err(Error::RelayRequest(
            "HTTP relay URLs are only allowed for loopback hosts".into(),
        )),
        _ => Err(Error::RelayRequest(
            "relay URL must use https, or http only to a loopback host".into(),
        )),
    }
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn relay_request_url(base: &str, path: &str) -> Result<Url> {
    let mut parsed = parse_relay_url(base)?;
    let joined = format!("{}{path}", parsed.path().trim_end_matches('/'));
    parsed.set_path(&joined);
    Ok(parsed)
}

fn http_agent_builder() -> ureq::AgentBuilder {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(20))
        .timeout_write(Duration::from_secs(20))
        .timeout(Duration::from_secs(30))
        .redirects(0)
}

fn http_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| http_agent_builder().build())
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
    let url = relay_request_url(base_url, "/inbox")?;
    let resp = with_key(http_agent().request_url("POST", &url), api_key)
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
    push_with_trees_until(base_url, api_key, envelope, trees, None)
}

/// Like [`push_with_trees`], and stamps a UTC envelope expiry the host scan
/// will delete after.
pub fn push_with_trees_until(
    base_url: &str,
    api_key: &str,
    envelope: &[u8],
    trees: &[PublicTree],
    expires_at: Option<&str>,
) -> Result<InboxAccepted> {
    let body = InboxPush {
        bytes: base64::engine::general_purpose::STANDARD.encode(envelope),
        trees: trees.to_vec(),
        expires_at: expires_at.map(str::to_owned),
    };
    let json = serde_json::to_string(&body).map_err(|e| Error::RelayRequest(e.to_string()))?;
    let url = relay_request_url(base_url, "/inbox")?;
    let resp = with_key(http_agent().request_url("POST", &url), api_key)
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
    let mut url = relay_request_url(base_url, "/inbox")?;
    if !params.is_empty() {
        url.set_query(Some(&params.join("&")));
    }
    let resp = with_key(http_agent().request_url("GET", &url), api_key).call();
    read_json(resp)
}

/// Mint a bearer via `POST /api/v1/{provider_id}/register`.
/// The caller must prove listed service-provider hardware; no API key.
pub fn register(
    base_url: &str,
    provider_id: &str,
    request: &RegisterRequest,
) -> Result<RegisterResponse> {
    let json = serde_json::to_string(request).map_err(|e| Error::RelayRequest(e.to_string()))?;
    let path = format!(
        "/api/{}/{}/register",
        super::register::API_VERSION,
        urlencoding_label(provider_id)
    );
    let url = relay_request_url(base_url, &path)?;
    let resp = http_agent()
        .request_url("POST", &url)
        .set("Content-Type", "application/json")
        .send_string(&json);
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
    let url = relay_request_url(base_url, "/keycheck")?;
    let resp = http_agent()
        .request_url("POST", &url)
        .set("Content-Type", "application/json")
        .send_string(&json);
    read_json(resp)
}

/// Challenge the relay for a KeyQuorum-signed provider certificate and a
/// signature over a fresh nonce. Official clients call this *before*
/// sending a bearer so a modified host cannot skip authorization.
pub fn authenticate_provider(
    base_url: &str,
    root_public_key: &[u8; 32],
    now_utc: &str,
    revoked: &HashSet<String>,
) -> Result<Certificate> {
    let challenge = provider::random_challenge();
    let body = ProviderIdentityRequest {
        challenge: base64::engine::general_purpose::STANDARD.encode(challenge),
    };
    let json = serde_json::to_string(&body).map_err(|e| Error::RelayRequest(e.to_string()))?;
    let url = relay_request_url(base_url, "/provider-identity")?;
    let result = http_agent()
        .request_url("POST", &url)
        .set("Content-Type", "application/json")
        .send_string(&json);
    let response: ProviderIdentityResponse = match result {
        Ok(resp) => {
            let body = resp
                .into_string()
                .map_err(|e| Error::RelayRequest(e.to_string()))?;
            serde_json::from_str(&body).map_err(|_| Error::UntrustedRelay)?
        }
        Err(ureq::Error::Status(503, _)) => return Err(Error::UntrustedRelay),
        Err(ureq::Error::Status(400, _)) => return Err(Error::InvalidProviderChallenge),
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            return Err(Error::RelayRequest(format!("HTTP {code}: {body}")));
        }
        Err(e) => return Err(Error::RelayRequest(e.to_string())),
    };
    let cert_bytes = base64::engine::general_purpose::STANDARD
        .decode(response.certificate.as_bytes())
        .map_err(|_| Error::UntrustedRelay)?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(response.signature.as_bytes())
        .map_err(|_| Error::UntrustedRelay)?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| Error::UntrustedRelay)?;
    let cert = provider::verify_certificate(root_public_key, &cert_bytes, now_utc, revoked)?;
    provider::verify_challenge(&cert, &challenge, &signature)?;
    Ok(cert)
}

/// Replace the relay's canonical public tree (admin scope).
pub fn publish_tree(base_url: &str, api_key: &str, tree: &PublicTree) -> Result<PublicTree> {
    let body = serde_json::to_string(tree).map_err(|e| Error::RelayRequest(e.to_string()))?;
    let url = relay_request_url(base_url, "/trees")?;
    let resp = with_key(http_agent().request_url("PUT", &url), api_key)
        .set("Content-Type", "application/json")
        .send_string(&body);
    read_json(resp)
}

/// Fetch the public-tree slice for this pull key's bound fingerprint.
pub fn fetch_tree_context(base_url: &str, api_key: &str, label: &str) -> Result<PublicTree> {
    let path = format!("/trees/{}/context", urlencoding_label(label));
    let url = relay_request_url(base_url, &path)?;
    let resp = with_key(http_agent().request_url("GET", &url), api_key).call();
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
mod tests;
