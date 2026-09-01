//! Axum router for the mailbox relay. Handlers never unseal envelopes.

use super::api_key::{self, ApiKeyInfo, ApiKeyScope, CreatedApiKey, NewApiKey};
use super::client::{ErrorBody, InboxAccepted, InboxEnvelope, InboxList};
use super::mailbox;
use super::org_tree;
use crate::error::Error;
use crate::key_tree::{PublicEdge, PublicNode, PublicTree};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_http::trace::TraceLayer;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
}

impl AppState {
    pub fn new(conn: Connection) -> Self {
        Self {
            db: Arc::new(Mutex::new(conn)),
        }
    }
}

struct ApiToken(String);

impl<S> FromRequestParts<S> for ApiToken
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        token_from_headers(&parts.headers).map(ApiToken)
    }
}

fn token_from_headers(headers: &HeaderMap) -> Result<String, ApiError> {
    if let Some(value) = headers.get(AUTHORIZATION) {
        let s = value.to_str().map_err(|_| ApiError::unauthorized())?;
        if let Some(token) = s.strip_prefix("Bearer ") {
            if !token.is_empty() {
                return Ok(token.to_string());
            }
        }
    }
    if let Some(value) = headers.get("x-api-key") {
        let s = value.to_str().map_err(|_| ApiError::unauthorized())?;
        if !s.is_empty() {
            return Ok(s.to_string());
        }
    }
    Err(ApiError::unauthorized())
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".to_string(),
        }
    }
}

impl From<Error> for ApiError {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidApiKey | Error::ApiKeyExpired | Error::ApiKeyRevoked => {
                Self::unauthorized()
            }
            Error::ApiKeyScopeDenied => Self {
                status: StatusCode::FORBIDDEN,
                message: "forbidden".to_string(),
            },
            Error::InvalidApiKeyRequest
            | Error::InvalidBridgePackage
            | Error::InvalidPublicKey
            | Error::InvalidTreeSpec
            | Error::DuplicateNodeLabel
            | Error::InvalidBridge => Self {
                status: StatusCode::BAD_REQUEST,
                message: err.to_string(),
            },
            Error::ApiKeyNotFound | Error::TreeNotFound | Error::NodeNotFound => Self {
                status: StatusCode::NOT_FOUND,
                message: err.to_string(),
            },
            Error::BundleFieldTooLarge => Self {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                message: err.to_string(),
            },
            other => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: other.to_string(),
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

async fn with_conn<T, F>(state: &AppState, f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> crate::error::Result<T> + Send + 'static,
{
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().expect("relay sqlite mutex poisoned");
        f(&conn)
    })
    .await
    .expect("relay db worker")
    .map_err(ApiError::from)
}

#[derive(Serialize, ToSchema)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Deserialize, IntoParams)]
struct InboxQuery {
    after: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
struct CreateApiKeyBody {
    scope: String,
    recipient_fingerprint: Option<String>,
    label: Option<String>,
    ttl_seconds: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct ApiKeyCreated {
    id: i64,
    token: String,
    scope: String,
    recipient_fingerprint: Option<String>,
    label: Option<String>,
    created_at: String,
    expires_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct ApiKeyView {
    id: i64,
    scope: String,
    recipient_fingerprint: Option<String>,
    label: Option<String>,
    created_at: String,
    expires_at: Option<String>,
    revoked_at: Option<String>,
    last_used_at: Option<String>,
}

impl From<CreatedApiKey> for ApiKeyCreated {
    fn from(created: CreatedApiKey) -> Self {
        Self {
            id: created.info.id,
            token: created.token,
            scope: created.info.scope,
            recipient_fingerprint: created.info.recipient_fingerprint,
            label: created.info.label,
            created_at: created.info.created_at,
            expires_at: created.info.expires_at,
        }
    }
}

impl From<ApiKeyInfo> for ApiKeyView {
    fn from(info: ApiKeyInfo) -> Self {
        Self {
            id: info.id,
            scope: info.scope,
            recipient_fingerprint: info.recipient_fingerprint,
            label: info.label,
            created_at: info.created_at,
            expires_at: info.expires_at,
            revoked_at: info.revoked_at,
            last_used_at: info.last_used_at,
        }
    }
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("API key")
                        .build(),
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        health,
        post_inbox,
        get_inbox,
        create_key,
        list_keys,
        rotate_key,
        revoke_key,
        put_tree,
        get_tree_context
    ),
    components(
        schemas(
            HealthResponse,
            InboxAccepted,
            InboxEnvelope,
            InboxList,
            ErrorBody,
            CreateApiKeyBody,
            ApiKeyCreated,
            ApiKeyView,
            PublicTree,
            PublicNode,
            PublicEdge
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "inbox", description = "Opaque .kqpb envelope mailbox"),
        (name = "api-keys", description = "API key administration"),
        (name = "trees", description = "Canonical public split-tree topology")
    )
)]
struct ApiDoc;

#[utoipa::path(
    get,
    path = "/health",
    tag = "inbox",
    responses((status = 200, description = "Relay is up", body = HealthResponse))
)]
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

#[utoipa::path(
    post,
    path = "/inbox",
    tag = "inbox",
    request_body(content = [u8], content_type = "application/octet-stream"),
    responses(
        (status = 201, description = "Envelope stored", body = InboxAccepted),
        (status = 200, description = "Envelope already stored", body = InboxAccepted),
        (status = 400, description = "Malformed envelope", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 413, description = "Envelope too large", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn post_inbox(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    body: Bytes,
) -> Result<(StatusCode, Json<InboxAccepted>), ApiError> {
    if body.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::BundleFieldTooLarge.into());
    }
    let envelope = body.to_vec();
    let (id, fingerprint, duplicate) = with_conn(&state, move |conn| {
        api_key::authenticate(conn, &token, ApiKeyScope::InboxPush)?;
        mailbox::store(conn, &envelope)
    })
    .await?;
    let status = if duplicate {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status,
        Json(InboxAccepted {
            id,
            recipient_fingerprint: fingerprint,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/inbox",
    tag = "inbox",
    params(InboxQuery),
    responses(
        (status = 200, description = "Envelopes for this pull key", body = InboxList),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn get_inbox(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Query(query): Query<InboxQuery>,
) -> Result<Json<InboxList>, ApiError> {
    let after = query.after;
    let envelopes = with_conn(&state, move |conn| {
        let auth = api_key::authenticate(conn, &token, ApiKeyScope::InboxPull)?;
        let fingerprint = auth.recipient_fingerprint.ok_or(Error::ApiKeyScopeDenied)?;
        mailbox::list_after(conn, &fingerprint, after)
    })
    .await?;
    Ok(Json(InboxList {
        envelopes: envelopes
            .into_iter()
            .map(|item| InboxEnvelope {
                id: item.id,
                recipient_fingerprint: item.recipient_fingerprint,
                bytes: STANDARD.encode(&item.bytes),
            })
            .collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api-keys",
    tag = "api-keys",
    request_body = CreateApiKeyBody,
    responses(
        (status = 201, description = "API key created; bearer shown once", body = ApiKeyCreated),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn create_key(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Json(body): Json<CreateApiKeyBody>,
) -> Result<(StatusCode, Json<ApiKeyCreated>), ApiError> {
    let created = with_conn(&state, move |conn| {
        api_key::authenticate(conn, &token, ApiKeyScope::Admin)?;
        let scope = ApiKeyScope::parse(&body.scope)?;
        api_key::create(
            conn,
            &NewApiKey {
                scope,
                recipient_fingerprint: body.recipient_fingerprint,
                label: body.label,
                ttl_seconds: body.ttl_seconds,
            },
        )
    })
    .await?;
    Ok((StatusCode::CREATED, Json(created.into())))
}

#[utoipa::path(
    get,
    path = "/api-keys",
    tag = "api-keys",
    responses(
        (status = 200, description = "API keys without bearers", body = [ApiKeyView]),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn list_keys(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
) -> Result<Json<Vec<ApiKeyView>>, ApiError> {
    let keys = with_conn(&state, move |conn| {
        api_key::authenticate(conn, &token, ApiKeyScope::Admin)?;
        api_key::list(conn)
    })
    .await?;
    Ok(Json(keys.into_iter().map(ApiKeyView::from).collect()))
}

#[utoipa::path(
    post,
    path = "/api-keys/{id}/rotate",
    tag = "api-keys",
    params(("id" = i64, Path, description = "API key id")),
    responses(
        (status = 200, description = "Replacement bearer shown once", body = ApiKeyCreated),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Unknown key", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn rotate_key(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Path(id): Path<i64>,
) -> Result<Json<ApiKeyCreated>, ApiError> {
    let created = with_conn(&state, move |conn| {
        api_key::authenticate(conn, &token, ApiKeyScope::Admin)?;
        api_key::rotate(conn, id)
    })
    .await?;
    Ok(Json(created.into()))
}

#[utoipa::path(
    post,
    path = "/api-keys/{id}/revoke",
    tag = "api-keys",
    params(("id" = i64, Path, description = "API key id")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Unknown key", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn revoke_key(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    with_conn(&state, move |conn| {
        api_key::authenticate(conn, &token, ApiKeyScope::Admin)?;
        api_key::revoke(conn, id)
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    put,
    path = "/trees",
    tag = "trees",
    request_body = PublicTree,
    responses(
        (status = 200, description = "Public tree replaced", body = PublicTree),
        (status = 400, description = "Malformed tree", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn put_tree(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Json(tree): Json<PublicTree>,
) -> Result<Json<PublicTree>, ApiError> {
    let stored = with_conn(&state, move |conn| {
        api_key::authenticate(conn, &token, ApiKeyScope::Admin)?;
        org_tree::put_public_tree(conn, &tree)
    })
    .await?;
    Ok(Json(stored))
}

#[utoipa::path(
    get,
    path = "/trees/{label}/context",
    tag = "trees",
    params(("label" = String, Path, description = "keys.label of the published tree")),
    responses(
        (status = 200, description = "Visible public-tree slice for this pull key", body = PublicTree),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Unknown tree or fingerprint", body = ErrorBody)
    ),
    security(("api_key" = []))
)]
async fn get_tree_context(
    State(state): State<AppState>,
    ApiToken(token): ApiToken,
    Path(label): Path<String>,
) -> Result<Json<PublicTree>, ApiError> {
    let slice = with_conn(&state, move |conn| {
        let auth = api_key::authenticate(conn, &token, ApiKeyScope::InboxPull)?;
        let fingerprint = auth.recipient_fingerprint.ok_or(Error::ApiKeyScopeDenied)?;
        org_tree::context_for_fingerprint(conn, &label, &fingerprint)
    })
    .await?;
    Ok(Json(slice))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/health", get(health))
        .route("/inbox", post(post_inbox).get(get_inbox))
        .route("/api-keys", post(create_key).get(list_keys))
        .route("/api-keys/{id}/rotate", post(rotate_key))
        .route("/api-keys/{id}/revoke", post(revoke_key))
        .route("/trees", put(put_tree))
        .route("/trees/{label}/context", get(get_tree_context))
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
