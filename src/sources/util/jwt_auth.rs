use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, LazyLock, Weak};
use tokio::sync::Mutex;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use openssl::x509::X509;
use regex::Regex;
use serde_json::Value;
use vector_lib::configurable::configurable_component;
use vector_lib::event::Event;
use vrl::path::{parse_target_path, OwnedTargetPath};

use crate::http::HttpClient;

/// Shorthand for the decoded JWT claims map used throughout this module.
type Claims = serde_json::Map<String, Value>;

/// Pre-parsed path for the `auth_field_name` log/trace metadata field.
pub(crate) static AUTH_FIELD_NAME_PATH: LazyLock<OwnedTargetPath> =
    LazyLock::new(|| parse_target_path("auth_field_name").expect("valid static path"));

/// Pre-parsed path for the `auth_field_value` log/trace metadata field.
pub(crate) static AUTH_FIELD_VALUE_PATH: LazyLock<OwnedTargetPath> =
    LazyLock::new(|| parse_target_path("auth_field_value").expect("valid static path"));

/// Metric tag key for the auth field name (metrics use plain string keys).
pub(crate) const AUTH_FIELD_NAME_TAG: &str = "auth_field_name";

/// Metric tag key for the auth field value.
pub(crate) const AUTH_FIELD_VALUE_TAG: &str = "auth_field_value";

/// JWT claim carrying the site's version at token-issue time (stamped by the
/// manager's auth-service — OBE-9896). Read for telemetry / per-version policy;
/// absent for older sites whose tokens predate the claim.
const SITE_VERSION_CLAIM: &str = "site_version";

/// Errors returned by [`Auth::authenticate`] (request-level).
#[derive(Debug, PartialEq)]
pub enum AuthError {
    /// The `authorization` header was present but the token is invalid, malformed, expired,
    /// or failed signature verification.
    ///
    /// Maps to HTTP 401 / gRPC `Unauthenticated`. Reject the entire request.
    InvalidToken(&'static str),
}

/// Errors produced by [`EventValidator::check`] (per-event).
///
/// Named after the equivalent HTTP status codes so the mapping to gRPC response
/// codes and metric outcome labels is unambiguous.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthEventError {
    /// The configured auth field was absent from the event or held a non-string value.
    ///
    /// The request JWT itself was valid — only the per-event authorization field is missing.
    AuthorizationMissing,

    /// The field value was present but is not listed in the token's membership claim.
    ///
    /// Equivalent to HTTP 403 — identity is known but not permitted.
    /// Maps to gRPC `PermissionDenied`.
    Forbidden,
}

impl AuthEventError {
    /// Short label used as a metric tag value for the `outcome` dimension.
    pub fn label(&self) -> &'static str {
        match self {
            AuthEventError::AuthorizationMissing => "authorization_missing",
            AuthEventError::Forbidden => "forbidden",
        }
    }
}

/// Compiled form of the JWT membership-claim configuration.
///
/// Built once in [`AuthConfig::build`] from the raw config strings and stored
/// in [`Inner`] so the hot path (per-request token extraction) pays no
/// allocation or compilation cost.
#[derive(Clone, Debug)]
pub enum MembershipClaim {
    /// Direct array lookup: all string values in the named claim are returned
    /// as the allowed-values set.
    Identity(String),
    /// Regex-filtered lookup: only values from the named claim that produce a
    /// match under the compiled pattern are included in the allowed-values set.
    /// The matched substring (not the full value) is what enters the set.
    Regexp(String, Regex),
}

impl MembershipClaim {
    fn claim_name(&self) -> &str {
        match self {
            MembershipClaim::Identity(name) | MembershipClaim::Regexp(name, _) => name.as_str(),
        }
    }

    /// Extract the allowed-values set from a decoded token's claims map.
    ///
    /// Returns `Err(InvalidToken)` if the named claim is absent, has the wrong
    /// type (`Identity` requires a JSON array; `Regexp` requires a JSON string),
    /// or yields an empty set (empty array, no-match, all-optional groups unmatched).
    pub fn extract(
        &self,
        claims: &Claims,
    ) -> Result<BTreeSet<String>, AuthError> {
        let value = claims
            .get(self.claim_name())
            .ok_or(AuthError::InvalidToken("token missing membership claim"))?;

        let set = match self {
            MembershipClaim::Identity(_) => {
                // Expects a JSON array.
                let array = value
                    .as_array()
                    .ok_or(AuthError::InvalidToken(
                        "token missing membership claim (or is not a list of strings)",
                    ))?;
                let mut set = BTreeSet::new();
                for v in array.iter().filter_map(Value::as_str) {
                    set.insert(v.to_owned());
                }
                set
            }
            MembershipClaim::Regexp(_, re) => {
                // Expects a JSON string — standard for scalar claims like `email`.
                let s = value
                    .as_str()
                    .ok_or(AuthError::InvalidToken("membership claim must be a string"))?;
                let caps = re
                    .captures(s)
                    .ok_or(AuthError::InvalidToken("token missing membership claim"))?;
                let mut set = BTreeSet::new();
                // skip(1): index 0 is the full match; only explicit capture groups enter the set.
                for m in caps.iter().skip(1).flatten() {
                    set.insert(m.as_str().to_owned());
                }
                set
            }
        };
        if set.is_empty() {
            return Err(AuthError::InvalidToken("token missing membership claim"));
        }
        Ok(set)
    }
}

/// Source of a PEM value — either inline or loaded from a file at startup.
///
/// Used by both [`Authority::PublicKey`] (bare RSA public key PEM) and
/// [`Authority::TlsCert`] (X.509 certificate PEM). The semantic distinction
/// between "this is a public key" and "this is a certificate" is carried by
/// the [`Authority`] variant; this type only models the I/O shape.
///
/// ## Examples
///
/// Inline (use Vector's `${VAR}` interpolation for env vars):
/// ```toml
/// pub_key.type  = "inline"
/// pub_key.value = "${RSA_PUBLIC_KEY}"
/// ```
///
/// File path (preferred for Kubernetes ConfigMap / secret volume mounts — the
/// file is read once at source startup):
/// ```toml
/// pub_key.type = "file"
/// pub_key.path = "/etc/certs/auth.pem"
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum AuthorityData {
    /// Inline PEM value.
    ///
    /// Supports Vector's `${ENV_VAR}` interpolation. The value is read once at startup.
    Inline {
        /// PEM-encoded value (RSA public key or X.509 certificate, depending
        /// on the enclosing [`Authority`] variant).
        value: String,
    },

    /// Path to a file containing the PEM.
    ///
    /// Preferred for Kubernetes ConfigMap or secret volume mounts.
    /// The file is read once at source startup.
    File {
        /// Path to the PEM file.
        path: String,
    },
}

/// JWKS endpoint source (Keycloak / Auth0 / Okta / Cognito / Google / any
/// OIDC-compliant IdP). The JWKS is fetched at startup, indexed by `kid`,
/// and refreshed both periodically and reactively when a token arrives with
/// a `kid` not in the cache.
///
/// Selected via the [`Authority::Jwks`] variant on [`AuthConfig`].
///
/// ## Example
///
/// ```toml
/// [sources.my_source.auth.jwks]
/// jwks_url = "https://kc.example/realms/master/protocol/openid-connect/certs"
/// refresh_interval_secs = 300
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct JwksAuthority {
    /// URL of the JWKS endpoint. Must return a JSON document of the form
    /// `{"keys": [<JWK>...]}` as defined by RFC 7517.
    pub jwks_url: String,

    /// Background refresh interval, in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_jwks_refresh_interval_secs")]
    pub refresh_interval_secs: u64,

    /// Per-fetch timeout, in seconds. Applies to both the initial fetch
    /// and subsequent refreshes. Default: 10.
    #[serde(default = "default_jwks_fetch_timeout_secs")]
    pub fetch_timeout_secs: u64,

    /// Minimum interval between reactive (on-unknown-kid) refreshes, in
    /// seconds. Acts as a cooldown to prevent refresh storms triggered by
    /// adversarial traffic. Default: 30.
    #[serde(default = "default_jwks_min_reactive_refresh_secs")]
    pub min_reactive_refresh_secs: u64,
}

const fn default_jwks_refresh_interval_secs() -> u64 {
    86400 // 1 day
}

const fn default_jwks_fetch_timeout_secs() -> u64 {
    60
}

const fn default_jwks_min_reactive_refresh_secs() -> u64 {
    900 // 15 minutes
}

/// Event field paths used to extract the membership value for per-event auth.
///
/// The `default` path is used for all event types unless a more specific override is set.
/// For metric events, `metric_tag` is a tag key rather than a field path.
///
/// ## Example
///
/// ```toml
/// [sources.my_source.auth.value_path]
/// default    = "tenant_id"
/// metric_tag = "tenant_id"
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AuthValuePath {
    /// Field path (or metric tag key) used for all event types unless a type-specific
    /// override is configured.
    pub default: String,

    /// Field path for log events. Overrides `default` when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,

    /// Tag key for metric events. Overrides `default` when set.
    ///
    /// Note: for metrics `default` is also interpreted as a tag key if this field is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric_tag: Option<String>,

    /// Field path for trace events. Overrides `default` when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,
}

impl AuthValuePath {
    /// Returns the effective field path for a log event.
    pub fn for_log(&self) -> &str {
        self.log.as_deref().unwrap_or(&self.default)
    }

    /// Returns the effective tag key for a metric event.
    pub fn for_metric(&self) -> &str {
        self.metric_tag.as_deref().unwrap_or(&self.default)
    }

    /// Returns the effective field path for a trace event.
    pub fn for_trace(&self) -> &str {
        self.trace.as_deref().unwrap_or(&self.default)
    }
}

/// A pre-parsed event path paired with the original user-configured name.
///
/// The `name` is what gets stamped onto authorized events as the
/// `auth_field_name` metadata. The `path` is the parsed form used for the
/// per-event lookup — built once at config load so the hot path skips the
/// VRL path parser.
#[derive(Debug)]
pub struct CompiledPath {
    pub(crate) name: String,
    pub(crate) path: OwnedTargetPath,
}

impl CompiledPath {
    fn new(s: &str) -> Result<Self, vrl::path::PathParseError> {
        Ok(Self {
            name: s.to_string(),
            path: parse_target_path(s)?,
        })
    }
}

/// Runtime form of [`AuthValuePath`] with paths pre-parsed.
///
/// Built once by [`AuthConfig::build`]; held inside the `Arc<Inner>` so every
/// `EventValidator` borrows it for free.
#[derive(Debug)]
pub struct CompiledValuePath {
    pub(crate) log: CompiledPath,
    /// Metric tag keys are plain strings, not paths — no parse step.
    pub(crate) metric_tag: String,
    pub(crate) trace: CompiledPath,
}

impl TryFrom<&AuthValuePath> for CompiledValuePath {
    type Error = vrl::path::PathParseError;

    fn try_from(vp: &AuthValuePath) -> Result<Self, Self::Error> {
        Ok(Self {
            log: CompiledPath::new(vp.log.as_deref().unwrap_or(&vp.default))?,
            metric_tag: vp.metric_tag.as_deref().unwrap_or(&vp.default).to_string(),
            trace: CompiledPath::new(vp.trace.as_deref().unwrap_or(&vp.default))?,
        })
    }
}

/// Stamp the auth field name/value onto an authorized event.
///
/// Uses pre-parsed [`OwnedTargetPath`]s for log/trace inserts so the hot path
/// avoids re-parsing `"auth_field_name"` / `"auth_field_value"` per event.
pub fn add_auth_metadata(event: &mut Event, name: &str, value: &str) {
    match event {
        Event::Log(log) => {
            log.insert(&*AUTH_FIELD_NAME_PATH, name);
            log.insert(&*AUTH_FIELD_VALUE_PATH, value);
        }
        Event::Metric(metric) => {
            metric.replace_tag(AUTH_FIELD_NAME_TAG.to_owned(), name.to_owned());
            metric.replace_tag(AUTH_FIELD_VALUE_TAG.to_owned(), value.to_owned());
        }
        Event::Trace(trace) => {
            trace.insert(&*AUTH_FIELD_NAME_PATH, name);
            trace.insert(&*AUTH_FIELD_VALUE_PATH, value);
        }
    }
}

/// JWT signing algorithm.
///
/// Only applicable when `authority` is `pub_key` or `tls_cert`. For the
/// `jwks` authority, accepted algorithms are derived automatically from the
/// keys published by the JWKS endpoint — setting `algorithms` together with
/// `jwks` is a configuration error.
#[configurable_component]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthAlgorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    #[serde(rename = "RS256")]
    Rs256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    #[serde(rename = "RS384")]
    Rs384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    #[serde(rename = "RS512")]
    Rs512,
    /// RSASSA-PSS using SHA-256.
    #[serde(rename = "PS256")]
    Ps256,
    /// RSASSA-PSS using SHA-384.
    #[serde(rename = "PS384")]
    Ps384,
    /// RSASSA-PSS using SHA-512.
    #[serde(rename = "PS512")]
    Ps512,
    /// ECDSA using P-256 and SHA-256. Requires `jwks` authority.
    #[serde(rename = "ES256")]
    Es256,
    /// ECDSA using P-384 and SHA-384. Requires `jwks` authority.
    #[serde(rename = "ES384")]
    Es384,
}

impl From<AuthAlgorithm> for Algorithm {
    fn from(a: AuthAlgorithm) -> Self {
        match a {
            AuthAlgorithm::Rs256 => Algorithm::RS256,
            AuthAlgorithm::Rs384 => Algorithm::RS384,
            AuthAlgorithm::Rs512 => Algorithm::RS512,
            AuthAlgorithm::Ps256 => Algorithm::PS256,
            AuthAlgorithm::Ps384 => Algorithm::PS384,
            AuthAlgorithm::Ps512 => Algorithm::PS512,
            AuthAlgorithm::Es256 => Algorithm::ES256,
            AuthAlgorithm::Es384 => Algorithm::ES384,
        }
    }
}

/// Default allowlist: full RSA family.
///
/// Covers all real-world IdPs using RSA public keys. EC variants (`ES*`) are
/// intentionally excluded from the default — they require the `jwks` authority
/// and must be opted into explicitly so that existing static-PEM configurations
/// are not silently affected.
///
/// Excludes:
/// - HMAC (`HS*`): wrong key type; enables the well-known RS↔HS confusion attack
/// - `none`: never accepted by jsonwebtoken regardless
pub(crate) fn default_algorithms() -> Vec<AuthAlgorithm> {
    vec![
        AuthAlgorithm::Rs256,
        AuthAlgorithm::Rs384,
        AuthAlgorithm::Rs512,
        AuthAlgorithm::Ps256,
        AuthAlgorithm::Ps384,
        AuthAlgorithm::Ps512,
    ]
}

/// Source of the RSA public key used to verify auth token signatures.
///
/// Exactly one variant must be configured. Flattened into [`AuthConfig`], so the
/// variant key sits directly under `[auth]`:
///
/// ```toml
/// [auth]
/// pub_key.type  = "inline"
/// pub_key.value = "${RSA_PUBLIC_KEY}"
/// ```
///
/// or
///
/// ```toml
/// [auth]
/// tls_cert.type = "file"
/// tls_cert.path = "/etc/pki/tls/certs/jwt-signer.crt"
/// ```
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Authority {
    /// Bare RSA public key PEM (`BEGIN PUBLIC KEY` / `BEGIN RSA PUBLIC KEY`).
    #[serde(rename = "pub_key")]
    PublicKey(AuthorityData),
    /// X.509 certificate PEM; the embedded public key is extracted at startup.
    ///
    /// Useful when the JWT signer's key is distributed as a TLS / trust-bundle
    /// certificate. Only the public key bytes are kept at runtime — certificate
    /// validity windows, issuer chains, and revocation status are **not** checked.
    TlsCert(AuthorityData),
    /// JWKS endpoint (Keycloak / Auth0 / Okta / Cognito / any OIDC IdP).
    /// Multi-key, refreshes both periodically and reactively on unknown `kid`.
    Jwks(JwksAuthority),
}

impl Authority {
    /// Resolve the configured source into a runtime [`KeyStore`].
    ///
    /// For static variants this is a synchronous PEM parse. For [`Self::Jwks`]
    /// this performs the initial HTTPS fetch and spawns the background
    /// refresh task — fail-fast if the endpoint is unreachable.
    async fn build_key_store(&self) -> crate::Result<KeyStore> {
        match self {
            Authority::PublicKey(pk) => Self::static_key_from_pem(&pk.load("pub_key")?),
            Authority::TlsCert(cert) => {
                let pem = Self::extract_public_key_pem_from_cert_pem(&cert.load("tls_cert")?)?;
                Self::static_key_from_pem(&pem)
            }
            Authority::Jwks(cfg) => Ok(KeyStore::Jwks(JwksCache::new(cfg).await?)),
        }
    }

    fn static_key_from_pem(pem: &str) -> crate::Result<KeyStore> {
        let key = DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|error| format!("Failed to parse RSA public key PEM: {error}"))?;
        Ok(KeyStore::Static(Arc::new(key)))
    }

    /// Build the [`Validation`] for this authority.
    ///
    /// For static PEM authorities, validates the algorithm allowlist and builds a
    /// `Validation` pinned to the configured (or default) algorithms. For JWKS,
    /// rejects an explicit `algorithms` field (they are derived from the endpoint)
    /// and returns a base `Validation` used as a template for the per-alg map.
    fn build_validation(
        &self,
        algorithms: Option<&[AuthAlgorithm]>,
    ) -> crate::Result<Validation> {
        match self {
            Authority::Jwks(_) => {
                if algorithms.is_some() {
                    return Err(
                        "auth.algorithms is not applicable with `jwks` authority; \
                         accepted algorithms are derived from the keys published by the \
                         JWKS endpoint"
                            .into(),
                    );
                }
                Ok(Validation::new(Algorithm::RS256)) // base for per-alg map; not used directly
            }
            _ => {
                let default_algos = default_algorithms();
                let algos = algorithms.unwrap_or(&default_algos);
                if algos.is_empty() {
                    return Err("auth.algorithms must contain at least one algorithm".into());
                }
                // Seed with the first algorithm, then overwrite with the full list.
                // jsonwebtoken checks the token's `alg` header against this list and
                // rejects anything not present — this is what prevents alg:none and
                // RS↔HS confusion attacks.
                let mut v = Validation::new(algos[0].into());
                v.algorithms = algos.iter().copied().map(Algorithm::from).collect();
                Ok(v)
            }
        }
    }

    /// Build per-algorithm [`Validation`] objects for the JWKS hot path.
    ///
    /// Returns a non-empty map only for [`Self::Jwks`]; all other variants return
    /// an empty map (static PEM uses `validation` directly).
    fn expand_jwks_validations(&self, base: &Validation) -> HashMap<Algorithm, Validation> {
        match self {
            Authority::Jwks(_) => [
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::RS512,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::PS512,
                Algorithm::ES256,
                Algorithm::ES384,
            ]
            .into_iter()
            .map(|alg| {
                let mut v = base.clone();
                v.algorithms = vec![alg];
                (alg, v)
            })
            .collect(),
            _ => HashMap::new(),
        }
    }

    /// Parse an X.509 certificate PEM and emit a `BEGIN PUBLIC KEY` (SPKI) PEM of its
    /// embedded public key — the form `jsonwebtoken::DecodingKey::from_rsa_pem` accepts.
    fn extract_public_key_pem_from_cert_pem(cert_pem: &str) -> crate::Result<String> {
        let cert = X509::from_pem(cert_pem.as_bytes())
            .map_err(|error| format!("Failed to parse X.509 certificate PEM: {error}"))?;
        let pubkey = cert
            .public_key()
            .map_err(|error| format!("Failed to extract public key from certificate: {error}"))?;
        let pem_bytes = pubkey
            .public_key_to_pem()
            .map_err(|error| format!("Failed to encode extracted public key as PEM: {error}"))?;
        String::from_utf8(pem_bytes)
            .map_err(|error| format!("Extracted public key PEM was not valid UTF-8: {error}").into())
    }
}

/// Runtime verification key material. Two shapes:
///
/// - [`Self::Static`]: a single [`DecodingKey`] resolved at startup. The hot
///   path is a single pointer deref — no locks, no allocation.
/// - [`Self::Jwks`]: an [`ArcSwap`]-backed map keyed by `kid`. Reads are
///   lock-free atomic pointer loads; the background refresher swaps in a new
///   map on each successful fetch. Designed for the millions-of-requests-per-
///   second hot path.
enum KeyStore {
    Static(Arc<DecodingKey>),
    Jwks(Arc<JwksCache>),
}

/// Decoded JWKS, indexed by `kid`.
type KeyMap = BTreeMap<String, DecodingKey>;

/// Shared cache backing the [`Authority::Jwks`] variant.
///
/// Hot-path reads go through [`Self::snapshot`] which returns a lock-free
/// [`arc_swap::Guard`] over the current [`KeyMap`]. Refreshes — both periodic
/// (background tokio task) and reactive (on unknown `kid`) — produce a new
/// [`KeyMap`] and call [`ArcSwap::store`] to publish it atomically.
struct JwksCache {
    keys: ArcSwap<KeyMap>,
    fetcher: JwksFetcher,
    /// Last-refresh timestamp guarding the reactive-refresh cooldown.
    last_refresh: Mutex<Instant>,
    min_reactive_refresh: Duration,
}

impl JwksCache {
    /// Construct, perform the initial fetch (fail-fast), and spawn the
    /// background refresh task. Returns `Arc<Self>` so the refresh task can
    /// hold a `Weak` and self-terminate when the [`Auth`] is dropped.
    async fn new(cfg: &JwksAuthority) -> crate::Result<Arc<Self>> {
        let fetcher = JwksFetcher::new(cfg)?;
        let initial = fetcher.fetch().await.map_err(|error| {
            format!("auth.jwks: initial fetch from '{}' failed: {error}", cfg.jwks_url)
        })?;
        if initial.is_empty() {
            return Err(format!(
                "auth.jwks: '{}' returned no usable signing keys \
                 (none with `use=sig` and an RSA or EC key type)",
                cfg.jwks_url
            )
            .into());
        }
        let cache = Arc::new(Self {
            keys: ArcSwap::new(Arc::new(initial)),
            fetcher,
            // Subtract the cooldown so the very first reactive refresh is never
            // blocked. Without this, a key rotated right before startup would be
            // unreachable for `min_reactive_refresh_secs` seconds.
            last_refresh: Mutex::new(
                Instant::now() - Duration::from_secs(cfg.min_reactive_refresh_secs),
            ),
            min_reactive_refresh: Duration::from_secs(cfg.min_reactive_refresh_secs),
        });
        Self::spawn_refresher(Arc::downgrade(&cache), Duration::from_secs(cfg.refresh_interval_secs));
        Ok(cache)
    }

    fn spawn_refresher(weak: Weak<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            // Skip the immediate first firing — we already fetched in `new`.
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(strong) = weak.upgrade() else {
                    debug!(message = "JWKS refresher exiting: Auth dropped.");
                    return;
                };
                strong.try_update_keys().await;
            }
        });
    }

    /// Lock-free snapshot of the current key map. Caller holds the guard for
    /// the duration of `decode` so the borrow into the map remains valid.
    fn snapshot(&self) -> arc_swap::Guard<Arc<KeyMap>> {
        self.keys.load()
    }

    /// Trigger a one-shot reactive refresh, gated by the cooldown window.
    ///
    /// Concurrent callers: the cooldown timestamp is set *before* the network
    /// fetch, so a second caller that races past the gate sees the updated
    /// timestamp and returns without firing a duplicate request.
    async fn refresh_if_due(&self) {
        {
            let mut last = self.last_refresh.lock().await;
            if last.elapsed() < self.min_reactive_refresh {
                return;
            }
            *last = Instant::now();
        }
        self.try_update_keys().await;
    }

    /// Fetch a fresh key map and atomically swap it in on success.
    /// On empty response or error, keeps the previous keys and logs a warning.
    async fn try_update_keys(&self) {
        match self.fetcher.fetch().await {
            Ok(map) if map.is_empty() => {
                warn!(message = "JWKS refresh returned no usable keys; keeping previous keys.");
            }
            Ok(map) => {
                self.keys.store(Arc::new(map));
                *self.last_refresh.lock().await = Instant::now();
            }
            Err(error) => {
                warn!(message = "JWKS refresh failed; keeping previous keys.", %error);
            }
        }
    }
}

/// HTTPS fetcher for the JWKS endpoint.
///
/// Uses Vector's standard [`HttpClient`] so it shares TLS/proxy/user-agent
/// behavior with the rest of the binary. The [`ProxyConfig::from_env`] call
/// at construction time picks up the standard `HTTPS_PROXY` / `NO_PROXY`
/// environment variables automatically.
struct JwksFetcher {
    url: http::Uri,
    client: HttpClient,
    timeout: Duration,
}

impl JwksFetcher {
    fn new(cfg: &JwksAuthority) -> crate::Result<Self> {
        let url: http::Uri = cfg.jwks_url.parse().map_err(|error| {
            format!("auth.jwks.jwks_url '{}' is not a valid URL: {error}", cfg.jwks_url)
        })?;
        let proxy = vector_lib::config::proxy::ProxyConfig::from_env();
        let client = HttpClient::new(None, &proxy, &crate::app_info())
            .map_err(|error| format!("auth.jwks: failed to build HTTP client: {error}"))?;
        Ok(Self {
            url,
            client,
            timeout: Duration::from_secs(cfg.fetch_timeout_secs),
        })
    }

    async fn fetch(&self) -> crate::Result<KeyMap> {
        let request = http::Request::get(&self.url)
            .header(http::header::ACCEPT, "application/json")
            .body(hyper::Body::empty())
            .map_err(|error| format!("failed to build JWKS request: {error}"))?;

        let response = tokio::time::timeout(self.timeout, self.client.send(request))
            .await
            .map_err(|_| format!("timed out after {:?}", self.timeout))?
            .map_err(|error| format!("HTTP request failed: {error}"))?;

        if !response.status().is_success() {
            return Err(format!("JWKS endpoint returned HTTP {}", response.status()).into());
        }

        let bytes = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|error| format!("failed to read JWKS response body: {error}"))?;

        let jwk_set: JwkSet = serde_json::from_slice(&bytes)
            .map_err(|error| format!("JWKS response is not valid JSON: {error}"))?;

        Ok(self.build_key_map(jwk_set))
    }

    fn build_key_map(&self, jwk_set: JwkSet) -> KeyMap {
        let mut map = KeyMap::new();
        for jwk in &jwk_set.keys {
            // Skip non-signing keys (Keycloak publishes both `enc` and `sig`).
            if let Some(use_) = &jwk.common.public_key_use {
                if !matches!(use_, PublicKeyUse::Signature) {
                    continue;
                }
            }
            // Accept RSA and EC keys; skip symmetric (oct) and other key types.
            if !matches!(
                jwk.algorithm,
                AlgorithmParameters::RSA(_) | AlgorithmParameters::EllipticCurve(_)
            ) {
                continue;
            }
            let Some(kid) = jwk.common.key_id.clone() else {
                // `kid`-less JWKS entries are unusable: we can't look them up
                // per token without scanning every key. Skip with a hint.
                warn!(message = "JWKS entry skipped: missing `kid`.");
                continue;
            };
            match DecodingKey::from_jwk(jwk) {
                Ok(key) => {
                    map.insert(kid, key);
                }
                Err(error) => {
                    warn!(message = "JWKS entry skipped: failed to build decoding key.", %error);
                }
            }
        }
        map
    }
}

/// Config-layer representation of the membership claim.
///
/// Accepts either a plain claim name (string) or a claim name paired with a
/// regex pattern. The compiled [`MembershipClaimConfig`] is built once in
/// [`AuthConfig::build`] so no regex compilation happens on the hot path.
///
/// ## TOML examples
///
/// Plain (identity):
/// ```toml
/// membership_claim = "site_ids"
/// ```
///
/// Regex-filtered:
/// ```toml
/// membership_claim = { claim = "roles", pattern = "^tenant:[^:]+$" }
/// ```
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum MembershipClaimConfig {
    /// All string values in the named claim array are admitted as-is.
    Identity(String),
    /// Only claim values that match `pattern` are admitted; the matched
    /// substring enters the allowed-values set.
    Regexp {
        /// Name of the JWT claim whose string value is matched against `pattern`.
        claim: String,
        /// Regex pattern applied to the claim string. All capture groups from a
        /// successful match enter the allowed-values set; group 0 (full match) is excluded.
        pattern: String,
    },
}

impl MembershipClaimConfig {
    /// Compile the config-layer claim into its runtime form.
    ///
    /// Validates and compiles the regex pattern once at startup so the hot
    /// path (`MembershipClaim::extract`) never allocates or compiles.
    pub fn build(&self) -> crate::Result<MembershipClaim> {
        match self {
            Self::Identity(name) => Ok(MembershipClaim::Identity(name.clone())),
            Self::Regexp { claim, pattern } => {
                let re = Regex::new(pattern)
                    .map_err(|error| format!("auth.membership_claim pattern: {error}"))?;
                Ok(MembershipClaim::Regexp(claim.clone(), re))
            }
        }
    }
}

/// Auth configuration for sources.
///
/// `authority` selects the signing key source — a static PEM (`pub_key` /
/// `tls_cert`) or a live JWKS endpoint — and is flattened so its variant key
/// sits directly under `[auth]`. Static keys are parsed once at startup;
/// JWKS keys are fetched at startup and refreshed in the background.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Source of the signing key used to verify auth token signatures.
    ///
    /// Required — deserialization fails if no variant key is present.
    #[serde(flatten, deserialize_with = "deserialize_authority_required")]
    pub authority: Authority,

    /// JWT signing algorithms accepted for token verification.
    ///
    /// Only applicable when `authority` is `pub_key` or `tls_cert`. Tokens
    /// whose `alg` header is not in this list are rejected. Pinning the
    /// algorithm at the validator prevents `alg: none` and RS↔HS key-confusion
    /// attacks.
    ///
    /// Defaults to the full RSA family
    /// (`RS256`/`RS384`/`RS512` + `PS256`/`PS384`/`PS512`) when omitted.
    ///
    /// Must not be set when `authority` is `jwks` — accepted algorithms are
    /// derived automatically from the JWKS endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<AuthAlgorithm>>,

    /// Expected `iss` (issuer) claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Expected `aud` (audience) claim values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,

    /// JWT claim used for membership checks and per-event field stamping.
    ///
    /// Accepts a plain claim name (`"site_ids"`) or a claim name with a regex
    /// pattern (`{ claim = "roles", pattern = "^tenant:[^:]+$" }`). See
    /// [`MembershipClaimConfig`] for the full format.
    ///
    /// When absent, membership checking and field stamping are both skipped —
    /// all events are accepted regardless of their field values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_claim: Option<MembershipClaimConfig>,

    /// Event field paths used to extract the membership value for per-event auth.
    ///
    /// When set, each event's field at the configured path is looked up and checked
    /// against the token's membership claim. Events without a matching value are
    /// filtered out. When absent, no per-event filtering is applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_path: Option<AuthValuePath>,
}

/// Replace serde's flattened-enum error with an actionable message naming the
/// expected variant keys. Other errors (typos in inner fields, bad `type`
/// values) are passed through with an `auth.authority` prefix so the failing
/// config path is unambiguous.
fn deserialize_authority_required<'de, D>(d: D) -> Result<Authority, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    use serde::Deserialize;

    Authority::deserialize(d).map_err(|original| {
        let msg = original.to_string();
        if msg.contains("no variant of enum") {
            D::Error::custom(
                "auth: must set one of `pub_key`, `tls_cert`, or `jwks` \
                 (e.g. `pub_key.type = \"file\"`, `pub_key.path = \"/path/to/key.pem\"`)",
            )
        } else {
            D::Error::custom(format!("auth.authority: {msg}"))
        }
    })
}

impl AuthConfig {
    /// Builds the runtime [`Auth`] by resolving the configured [`Authority`]
    /// (a static PEM, a TLS cert via SPKI extraction, or a JWKS endpoint with
    /// initial fetch + background refresh) and assembling the verifier.
    ///
    /// All I/O and PEM parsing happen here — once at startup. The resulting
    /// [`Auth`] is cheap to clone and holds no file handles. For the JWKS
    /// authority, build returns an error if the initial fetch fails so that
    /// misconfigurations surface at `vector validate` / source startup
    /// rather than at first-request time.
    pub async fn build(&self) -> crate::Result<Auth> {
        // Validate config (algorithm/authority compatibility) before any I/O.
        let mut validation = self.authority.build_validation(self.algorithms.as_deref())?;

        let key_store = self.authority.build_key_store().await?;

        if let Some(issuer) = &self.issuer {
            validation.set_issuer(&[issuer]);
        }

        if let Some(audiences) = &self.audience {
            validation.set_audience(audiences);
        } else {
            validation.validate_aud = false;
        }

        // For JWKS: precompute one `Validation` per supported algorithm so that
        // `authenticate` never clones or allocates a `Validation` on the hot path.
        let jwks_validations = self.authority.expand_jwks_validations(&validation);

        let value_path = self
            .value_path
            .as_ref()
            .map(CompiledValuePath::try_from)
            .transpose()
            .map_err(|error| format!("Failed to parse auth value_path: {error}"))?;

        let membership_claim = self.membership_claim
            .as_ref()
            .map(MembershipClaimConfig::build)
            .transpose()?;

        Ok(Auth(Arc::new(Inner {
            key_store,
            validation,
            jwks_validations,
            membership_claim,
            value_path,
        })))
    }
}

impl AuthorityData {
    /// Resolve to the PEM string. `kind` is the configuration field name
    /// (`"pub_key"` or `"tls_cert"`) used to make I/O failures point at
    /// the right config field.
    fn load(&self, kind: &str) -> crate::Result<String> {
        match self {
            Self::Inline { value } => Ok(value.clone()),
            Self::File { path } => std::fs::read_to_string(path).map_err(|error| {
                format!("Failed to read auth {kind} from '{path}': {error}").into()
            }),
        }
    }
}

// Private — holds the resolved key material and validation config behind Arc
// so Auth is cheap to clone across tokio tasks without copying RSA key bytes
// or duplicating the JWKS cache.
struct Inner {
    key_store: KeyStore,
    validation: Validation,
    /// Per-algorithm `Validation` objects for the JWKS hot path. Built once at
    /// startup so `authenticate` never allocates a `Validation` per request.
    /// Empty for static-PEM authorities.
    jwks_validations: HashMap<Algorithm, Validation>,
    membership_claim: Option<MembershipClaim>,
    value_path: Option<CompiledValuePath>,
}

/// Per-request auth context returned by a successful [`Auth::authenticate`] call.
///
/// Holds the list of allowed membership values extracted from the JWT claim.
/// Pass to per-event validation helpers in the source's event-processing loop.
pub struct AuthContext {
    /// `None` when `membership_claim` is absent — all events are admitted and
    /// field stamping is skipped. `Some` holds the extracted allowed-values set.
    pub(crate) allowed_values: Option<BTreeSet<String>>,
}

impl AuthContext {
    /// Returns `true` if `value` is present in the token's membership claim.
    ///
    /// Always returns `true` when no membership claim is configured.
    pub fn is_authorized(&self, value: &str) -> bool {
        match &self.allowed_values {
            Some(values) => values.contains(value),
            None => true,
        }
    }

    /// Bind this context to a [`CompiledValuePath`], producing an [`EventValidator`]
    /// that can be used directly in `.filter_map()` or `.map()` iterator chains.
    pub fn into_validator<'a>(
        &'a self,
        value_path: &'a CompiledValuePath,
    ) -> EventValidator<'a> {
        EventValidator {
            context: self,
            value_path,
        }
    }
}

/// Per-event validator produced by [`AuthContext::into_validator`].
///
/// Encapsulates the allowed-values list and the field-path configuration so
/// it can be used as a self-contained predicate in event-processing pipelines.
///
/// # Example
///
/// ```ignore
/// let validator = ctx.into_validator(value_path);
/// let authorized: Vec<Event> = events
///     .into_iter()
///     .filter_map(|mut event| {
///         match validator.check(&event) {
///             Ok((name, value)) => {
///                 add_auth_metadata(&mut event, &name, &value);
///                 Some(event)
///             }
///             Err(_) => None,
///         }
///     })
///     .collect();
/// ```
pub struct EventValidator<'a> {
    context: &'a AuthContext,
    value_path: &'a CompiledValuePath,
}

impl<'a> EventValidator<'a> {
    /// Validate a single event.
    ///
    /// # Returns
    ///
    /// * `Ok((field_name, field_value))` — the event is authorized. `field_name`
    ///   borrows the user-configured path string from the validator;
    ///   `field_value` is the value extracted from the event.
    /// * `Err(AuthEventError::AuthorizationMissing)` — the configured field is absent or
    ///   holds a non-string value; the event's identity cannot be determined.
    /// * `Err(AuthEventError::Forbidden)` — the field value is present but not listed
    ///   in the token's membership claim.
    pub fn check<'e>(
        &self,
        event: &'e Event,
    ) -> Result<(&'a str, Cow<'e, str>), AuthEventError> {
        let (field_name, field_value) = self.read_field(event);
        match field_value {
            Some(value) if self.context.is_authorized(&value) => Ok((field_name, value)),
            Some(_) => Err(AuthEventError::Forbidden),
            None => Err(AuthEventError::AuthorizationMissing),
        }
    }

    fn read_field<'e>(&self, event: &'e Event) -> (&'a str, Option<Cow<'e, str>>) {
        match event {
            Event::Log(log) => {
                let value = log.get(&self.value_path.log.path).and_then(|v| v.as_str());
                (self.value_path.log.name.as_str(), value)
            }
            Event::Metric(metric) => {
                let value = metric
                    .tag_value(&self.value_path.metric_tag)
                    .map(Cow::Owned);
                (self.value_path.metric_tag.as_str(), value)
            }
            Event::Trace(trace) => {
                let value = trace
                    .get(&self.value_path.trace.path)
                    .and_then(|v| v.as_str());
                (self.value_path.trace.name.as_str(), value)
            }
        }
    }
}

/// Runtime auth handle built from [`AuthConfig`].
///
/// Cheap to clone — all state is held behind an [`Arc`].
#[derive(Clone)]
pub struct Auth(Arc<Inner>);

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("membership_claim", &self.0.membership_claim)
            .finish_non_exhaustive()
    }
}

impl Auth {
    /// Returns the configured event field path config, if any.
    ///
    /// Returns `None` when no membership claim is configured — field stamping
    /// is skipped alongside membership checking in that case.
    pub fn value_path(&self) -> Option<&CompiledValuePath> {
        self.0.membership_claim.as_ref()?;
        self.0.value_path.as_ref()
    }

    /// Validate the request-level JWT and return an [`AuthContext`] for per-event validation.
    ///
    /// # Parameters
    ///
    /// * `authorization` — value of the `authorization` / `Authorization` header, if present.
    ///   Expected format: `"Bearer <jwt>"`.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(ctx))` — token is valid. Use [`AuthContext::is_authorized`] for per-event
    ///   membership checks against the extracted allowed-values list.
    /// * `Err(AuthError::InvalidToken)` — `authorization` was absent (a token is always
    ///   required), or the token is malformed/expired/bad-signature, wrong issuer/audience,
    ///   unsupported algorithm, or the membership claim is missing.
    pub async fn authenticate(
        &self,
        authorization: Option<&str>,
    ) -> Result<Option<AuthContext>, AuthError> {
        let Some(auth_value) = authorization else {
            // A token is always required (OBE-9898 removed the legacy
            // `require_token = false` bypass).
            return Err(AuthError::InvalidToken(
                "authorization header is required",
            ));
        };

        let token = strip_bearer_prefix(auth_value)
            .ok_or(AuthError::InvalidToken("authorization must use Bearer scheme"))?;

        let inner = &self.0;
        let token_data = match &inner.key_store {
            // Static key: single-pointer-deref hot path, no locks.
            KeyStore::Static(key) => decode_claims(token, key, &inner.validation)?,
            // JWKS: look up by token's `kid`. ArcSwap snapshot is lock-free.
            // On miss, trigger a cooldown-gated reactive refresh and retry once.
            KeyStore::Jwks(cache) => {
                let header = decode_header(token).map_err(|error| {
                    warn!(message = "JWT header parse failed.", %error);
                    AuthError::InvalidToken("invalid token header")
                })?;
                let kid = header.kid.as_deref().ok_or(AuthError::InvalidToken(
                    "token missing `kid` header",
                ))?;

                // jsonwebtoken v9 requires all entries in Validation::algorithms to share
                // the same AlgorithmFamily as the DecodingKey. Use the precomputed
                // per-algorithm Validation to avoid any hot-path allocation.
                let per_alg_validation = inner
                    .jwks_validations
                    .get(&header.alg)
                    .ok_or(AuthError::InvalidToken("unsupported algorithm"))?;

                // Fast path: key already in snapshot — no network needed.
                let fast_path_data = {
                    let snapshot = cache.snapshot();
                    snapshot
                        .get(kid)
                        .map(|key| decode_claims(token, key, per_alg_validation))
                        .transpose()?
                };

                if let Some(data) = fast_path_data {
                    data
                } else {
                    // Slow path: unknown kid → reactive refresh (cooldown-gated)
                    // → look up again. If still missing, the kid is genuinely
                    // not served by this IdP.
                    cache.refresh_if_due().await;
                    let snapshot = cache.snapshot();
                    let key = snapshot.get(kid).ok_or_else(|| {
                        warn!(message = "Token signed by unknown key.", kid = %kid);
                        AuthError::InvalidToken("unknown signing key")
                    })?;
                    decode_claims(token, key, per_alg_validation)?
                }
            }
        };

        // Surface the site's version (the manager stamps `site_version` as a JWT
        // claim — OBE-9896) for telemetry / future per-version policy. Absent for
        // older sites whose tokens predate the claim.
        if let Some(site_version) =
            token_data.claims.get(SITE_VERSION_CLAIM).and_then(Value::as_str)
        {
            debug!(message = "Authenticated site push.", %site_version);
        }

        let allowed_values = inner.membership_claim
            .as_ref()
            .map(|c| c.extract(&token_data.claims))
            .transpose()?;
        Ok(Some(AuthContext { allowed_values }))
    }
}

fn token_validation_failed(err: jsonwebtoken::errors::Error) -> AuthError {
    warn!(message = "Token validation failed.", error = %err);
    AuthError::InvalidToken("invalid or expired token")
}

fn decode_claims(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<Claims>, AuthError> {
    decode::<Claims>(token, key, validation).map_err(token_validation_failed)
}

/// Strip the `Bearer` auth scheme from a header value, case-insensitively and
/// tolerant of any whitespace between the scheme and the token.
fn strip_bearer_prefix(value: &str) -> Option<&str> {
    let trimmed = value.trim_start();
    if trimmed.len() < 6 || !trimmed.as_bytes()[..6].eq_ignore_ascii_case(b"Bearer") {
        return None;
    }
    let rest = &trimmed[6..];
    // require at least one whitespace separator between the scheme and the token
    if !rest.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let token = rest.trim_start();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

#[cfg(all(test, feature = "sources-vector"))]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::io::Write;

    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    use super::*;
    use crate::test_util::jwt_auth::{
        bearer, build_auth, make_token, now_secs, TEST_CERT, TEST_PRIVATE_KEY, TEST_PUBLIC_KEY,
    };

    // Construct a baseline `AuthConfig` from the given authority, using the
    // permissive defaults the tests below want (no issuer/audience/value_path).
    // Individual tests override fields as needed.
    fn cfg_with(authority: Authority) -> AuthConfig {
        AuthConfig {
            authority,
            issuer: None,
            audience: None,
            membership_claim: Some(MembershipClaimConfig::Identity("site_ids".to_string())),
            value_path: None,
            algorithms: None,
        }
    }

    fn inline_public_key() -> Authority {
        Authority::PublicKey(AuthorityData::Inline {
            value: TEST_PUBLIC_KEY.to_string(),
        })
    }

    fn inline_tls_cert() -> Authority {
        Authority::TlsCert(AuthorityData::Inline {
            value: TEST_CERT.to_string(),
        })
    }

    // ── AuthConfig::build ────────────────────────────────────────────────────

    #[tokio::test]
    async fn build_from_inline_pem_succeeds() {
        assert!(cfg_with(inline_public_key()).build().await.is_ok());
    }

    #[tokio::test]
    async fn build_from_file_pem_succeeds() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(TEST_PUBLIC_KEY.as_bytes()).unwrap();

        let cfg = cfg_with(Authority::PublicKey(AuthorityData::File {
            path: f.path().to_str().unwrap().into(),
        }));
        assert!(cfg.build().await.is_ok());
    }

    #[tokio::test]
    async fn build_with_invalid_pem_fails() {
        let cfg = cfg_with(Authority::PublicKey(AuthorityData::Inline {
            value: "this is not a PEM".to_string(),
        }));
        assert!(cfg.build().await.is_err());
    }

    #[tokio::test]
    async fn build_with_missing_pem_file_fails() {
        let cfg = cfg_with(Authority::PublicKey(AuthorityData::File {
            path: "/nonexistent/path/key.pem".to_string(),
        }));
        assert!(cfg.build().await.is_err());
    }

    #[tokio::test]
    async fn build_with_missing_tls_cert_file_fails() {
        let cfg = cfg_with(Authority::TlsCert(AuthorityData::File {
            path: "/nonexistent/path/auth.crt".to_string(),
        }));
        assert!(cfg.build().await.is_err());
    }

    #[tokio::test]
    async fn build_from_inline_tls_cert_succeeds() {
        let auth = cfg_with(inline_tls_cert())
            .build()
            .await
            .expect("AuthConfig::build should accept an X.509 certificate PEM via tls_cert");

        // The public key extracted from the cert must actually verify tokens
        // signed by the matching test private key — not just parse cleanly.
        let token = make_token(HashMap::new());
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    #[tokio::test]
    async fn build_from_tls_cert_file_succeeds() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(TEST_CERT.as_bytes()).unwrap();

        let cfg = cfg_with(Authority::TlsCert(AuthorityData::File {
            path: f.path().to_str().unwrap().into(),
        }));
        assert!(cfg.build().await.is_ok());
    }

    #[tokio::test]
    async fn build_with_malformed_tls_cert_pem_fails() {
        let cfg = cfg_with(Authority::TlsCert(AuthorityData::Inline {
            value: "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n"
                .to_string(),
        }));
        assert!(cfg.build().await.is_err());
    }

    #[tokio::test]
    async fn build_with_public_key_pem_in_tls_cert_field_fails() {
        // tls_cert is strictly X.509 — feeding it a bare RSA public key
        // PEM must surface the cert parser's failure, not silently accept it.
        let cfg = cfg_with(Authority::TlsCert(AuthorityData::Inline {
            value: TEST_PUBLIC_KEY.to_string(),
        }));
        assert!(cfg.build().await.is_err());
    }

    // No symmetric `cert PEM in pub_key field` negative test: jsonwebtoken's
    // `DecodingKey::from_rsa_pem` will *sometimes* accept a `BEGIN CERTIFICATE`
    // PEM (it extracts the first ASN.1 BitString, which is the SPKI bitstring
    // for simple RSA certs) and *sometimes* reject it (`InvalidKeyFormat`,
    // depending on the cert's extension layout). That's upstream behavior, not
    // ours — we don't promise either outcome, so we don't assert it.

    // No "both authority variants set" runtime check is needed: the
    // `Authority` enum makes that state unrepresentable in Rust, and the
    // externally-tagged serde form rejects TOML with two variant keys at
    // parse time. See `authority_with_multiple_variants_in_toml_fails`.

    // ── Auth::authenticate ───────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_token_returns_allowed_values() {
        let auth = build_auth(None, None).await;
        let token = make_token(HashMap::new());
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
        assert!(ctx.is_authorized("site-456"));
        assert!(!ctx.is_authorized("site-other"));
    }

    #[tokio::test]
    async fn non_bearer_scheme_rejected() {
        let auth = build_auth(None, None).await;
        let token = make_token(HashMap::new());
        let result = auth.authenticate(Some(&format!("Basic {token}"))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn malformed_token_rejected() {
        let auth = build_auth(None, None).await;
        let result = auth.authenticate(Some("Bearer not.a.jwt")).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let auth = build_auth(None, None).await;
        let mut extra = HashMap::new();
        extra.insert("exp", serde_json::json!(now_secs() - 3600));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn wrong_issuer_rejected() {
        let auth = build_auth(Some("https://expected.example.com/"), None).await;
        let mut extra = HashMap::new();
        extra.insert("iss", serde_json::json!("https://other.example.com/"));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn matching_issuer_passes() {
        let auth = build_auth(Some("https://expected.example.com/"), None).await;
        let mut extra = HashMap::new();
        extra.insert("iss", serde_json::json!("https://expected.example.com/"));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wrong_audience_rejected() {
        let auth = build_auth(None, Some(vec!["https://expected-api/"])).await;
        let mut extra = HashMap::new();
        extra.insert("aud", serde_json::json!(["https://other-api/"]));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn matching_audience_passes() {
        let auth = build_auth(None, Some(vec!["https://expected-api/"])).await;
        let mut extra = HashMap::new();
        extra.insert("aud", serde_json::json!(["https://expected-api/"]));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn missing_membership_claim_in_token_rejected() {
        let auth = build_auth(None, None).await;
        // Token has no site_ids claim at all.
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("user"));
        claims.insert("exp".into(), serde_json::json!(now_secs() + 3600));
        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap();
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn wrong_type_membership_claim_in_token_rejected() {
        // The claim is present but is a plain string instead of the required
        // array-of-strings. Must be rejected at `authenticate` rather than
        // silently treated as an empty allowlist.
        let auth = build_auth(None, None).await;
        let mut extra = HashMap::new();
        extra.insert("site_ids", serde_json::json!("site-123"));
        let token = make_token(extra);
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn custom_membership_claim_is_checked() {
        let mut cfg = cfg_with(inline_public_key());
        cfg.membership_claim = Some(MembershipClaimConfig::Identity("allowed_tenants".to_string()));
        let auth = cfg.build().await.unwrap();

        let mut extra = HashMap::new();
        extra.insert("allowed_tenants", serde_json::json!(["tenant-abc"]));
        let token = make_token(extra);

        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("tenant-abc"));
        assert!(!ctx.is_authorized("site-123")); // site-123 is in site_ids, not allowed_tenants
    }

    #[tokio::test]
    async fn invalid_regexp_pattern_fails_build() {
        let mut cfg = cfg_with(inline_public_key());
        cfg.membership_claim = Some(MembershipClaimConfig::Regexp {
            claim: "roles".to_string(),
            pattern: "[unclosed".to_string(),
        });
        let err = cfg.build().await.unwrap_err().to_string();
        assert!(
            err.contains("auth.membership_claim pattern"),
            "expected pattern compilation error, got: {err}",
        );
    }

    #[tokio::test]
    async fn regexp_membership_claim_capture_groups_are_authorized_values() {
        // Pattern extracts the tenant ID from an email claim string.
        // Capture group 1 ("42") becomes the authorized value — not the full email.
        let mut cfg = cfg_with(inline_public_key());
        cfg.membership_claim = Some(MembershipClaimConfig::Regexp {
            claim: "email".to_string(),
            pattern: r"^tenant_([0-9]+)@example\.com$".to_string(),
        });
        let auth = cfg.build().await.unwrap();

        let mut extra = HashMap::new();
        extra.insert("email", serde_json::json!("tenant_42@example.com"));
        let token = make_token(extra);

        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("42"));
        assert!(!ctx.is_authorized("tenant_42@example.com")); // full email not in set
        assert!(!ctx.is_authorized("tenant_42"));
    }

    #[tokio::test]
    async fn regexp_membership_claim_multiple_capture_groups() {
        // Both capture groups enter the set independently.
        let mut cfg = cfg_with(inline_public_key());
        cfg.membership_claim = Some(MembershipClaimConfig::Regexp {
            claim: "email".to_string(),
            pattern: r"^(tenant)_([0-9]+)@example\.com$".to_string(),
        });
        let auth = cfg.build().await.unwrap();

        let mut extra = HashMap::new();
        extra.insert("email", serde_json::json!("tenant_42@example.com"));
        let token = make_token(extra);

        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("tenant"));
        assert!(ctx.is_authorized("42"));
    }

    #[tokio::test]
    async fn regexp_membership_claim_no_match_is_rejected() {
        // Token is valid and the claim exists, but the pattern does not match.
        // The request is hard-rejected — same error as a missing claim.
        let mut cfg = cfg_with(inline_public_key());
        cfg.membership_claim = Some(MembershipClaimConfig::Regexp {
            claim: "email".to_string(),
            pattern: r"^tenant_([0-9]+)@example\.com$".to_string(),
        });
        let auth = cfg.build().await.unwrap();

        let mut extra = HashMap::new();
        extra.insert("email", serde_json::json!("admin@example.com"));
        let token = make_token(extra);

        assert!(matches!(
            auth.authenticate(Some(&bearer(&token))).await,
            Err(AuthError::InvalidToken(_)),
        ));
    }

    // ── algorithm allowlist ──────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_algorithms_list_fails_build() {
        let mut cfg = cfg_with(inline_public_key());
        cfg.algorithms = Some(vec![]);
        assert!(cfg.build().await.is_err());
    }

    #[tokio::test]
    async fn build_fails_on_invalid_value_path_expression() {
        // `CompiledValuePath::try_from` runs `parse_target_path` on each
        // configured string. A malformed path must surface as a build
        // failure with the documented `Failed to parse auth value_path`
        // prefix — not silently succeed.
        let mut cfg = cfg_with(inline_public_key());
        cfg.value_path = Some(AuthValuePath {
            default: ".[unterminated".to_string(),
            log: None,
            metric_tag: None,
            trace: None,
        });
        let err = cfg.build().await.unwrap_err().to_string();
        assert!(
            err.contains("Failed to parse auth value_path"),
            "expected value_path parse error, got: {err}",
        );
    }

    #[test]
    fn auth_event_error_labels_match_documented_metric_tags() {
        // These strings are emitted as the `outcome` tag on the per-event
        // auth metrics in `src/sources/vector/mod.rs`. Renaming them would
        // silently break dashboards / alerting that filter on this tag.
        assert_eq!(
            AuthEventError::AuthorizationMissing.label(),
            "authorization_missing"
        );
        assert_eq!(AuthEventError::Forbidden.label(), "forbidden");
    }

    #[tokio::test]
    async fn token_with_algorithm_not_in_allowlist_is_rejected() {
        // Allowlist only RS512; sign the token with RS256 → must be rejected.
        let mut cfg = cfg_with(inline_public_key());
        cfg.algorithms = Some(vec![AuthAlgorithm::Rs512]);
        let auth = cfg.build().await.unwrap();
        let token = make_token(HashMap::new()); // signed with RS256 by helper
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn token_with_algorithm_in_allowlist_is_accepted() {
        let mut cfg = cfg_with(inline_public_key());
        cfg.algorithms = Some(vec![AuthAlgorithm::Rs256, AuthAlgorithm::Rs512]);
        let auth = cfg.build().await.unwrap();
        let token = make_token(HashMap::new()); // signed with RS256
        assert!(auth.authenticate(Some(&bearer(&token))).await.is_ok());
    }

    // ── token requirement (a token is always required) ───────────────────────

    #[tokio::test]
    async fn missing_authorization_is_rejected() {
        let auth = build_auth(None, None).await;
        let result = auth.authenticate(None).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[tokio::test]
    async fn valid_token_is_accepted() {
        let auth = build_auth(None, None).await;
        let token = make_token(HashMap::new());
        assert!(auth.authenticate(Some(&bearer(&token))).await.is_ok());
    }

    #[tokio::test]
    async fn invalid_token_is_rejected() {
        let auth = build_auth(None, None).await;
        let result = auth.authenticate(Some("Bearer not.a.jwt")).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn default_algorithms_covers_rs_and_ps_family() {
        let algos = default_algorithms();
        assert!(algos.contains(&AuthAlgorithm::Rs256));
        assert!(algos.contains(&AuthAlgorithm::Rs384));
        assert!(algos.contains(&AuthAlgorithm::Rs512));
        assert!(algos.contains(&AuthAlgorithm::Ps256));
        assert!(algos.contains(&AuthAlgorithm::Ps384));
        assert!(algos.contains(&AuthAlgorithm::Ps512));
        assert_eq!(algos.len(), 6);
    }

    // ── AuthContext::is_authorized ───────────────────────────────────────────

    #[test]
    fn auth_context_is_authorized_checks_membership() {
        let ctx = AuthContext {
            allowed_values: Some(["foo", "bar"].into_iter().map(String::from).collect::<BTreeSet<_>>()),
        };
        assert!(ctx.is_authorized("foo"));
        assert!(ctx.is_authorized("bar"));
        assert!(!ctx.is_authorized("baz"));
    }

    // ── no membership_claim (token-only mode) ───────────────────────────────
    //
    // When `membership_claim` is `None` the auth module runs in token-only
    // mode: the token is fully validated (signature, expiry, issuer, audience)
    // but no claim is extracted for membership filtering, `AuthContext`
    // carries `allowed_values: None` (→ `is_authorized` always true), and
    // `Auth::value_path()` returns `None` so the caller never stamps events.

    async fn build_no_membership_auth() -> Auth {
        let mut cfg = cfg_with(inline_public_key());
        cfg.membership_claim = None;
        cfg.build().await.unwrap()
    }

    #[tokio::test]
    async fn no_membership_claim_valid_token_accepted() {
        // A token that has no site_ids claim at all must be accepted when
        // `membership_claim` is not configured — there is nothing to extract.
        let auth = build_no_membership_auth().await;
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("user"));
        claims.insert("exp".into(), serde_json::json!(now_secs() + 3600));
        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap();
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert_eq!(ctx.allowed_values, None);
    }

    #[tokio::test]
    async fn no_membership_claim_auth_context_allows_all_values() {
        // `allowed_values: None` means no filtering — `is_authorized` must
        // return true for every string, including arbitrary values that would
        // never appear in a real claim.
        let auth = build_no_membership_auth().await;
        let token = make_token(HashMap::new());
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
        assert!(ctx.is_authorized("anything"));
        assert!(ctx.is_authorized(""));
    }

    #[tokio::test]
    async fn no_membership_claim_invalid_token_still_rejected() {
        let auth = build_no_membership_auth().await;
        assert!(matches!(
            auth.authenticate(Some("Bearer not.a.jwt")).await,
            Err(AuthError::InvalidToken(_)),
        ));
    }

    #[tokio::test]
    async fn no_membership_claim_expired_token_still_rejected() {
        let auth = build_no_membership_auth().await;
        let mut extra = HashMap::new();
        extra.insert("exp", serde_json::json!(now_secs() - 3600));
        let token = make_token(extra);
        assert!(matches!(
            auth.authenticate(Some(&bearer(&token))).await,
            Err(AuthError::InvalidToken(_)),
        ));
    }

    #[tokio::test]
    async fn no_membership_claim_value_path_is_none_skipping_stamping() {
        // Even when `value_path` is explicitly configured, `Auth::value_path()`
        // must return `None` when `membership_claim` is absent — the caller
        // guards all stamping logic on `auth.value_path().is_some()`.
        let mut cfg = cfg_with(inline_public_key());
        cfg.membership_claim = None;
        cfg.value_path = Some(AuthValuePath {
            default: "tenant_id".into(),
            log: None,
            metric_tag: None,
            trace: None,
        });
        let auth = cfg.build().await.unwrap();
        assert!(auth.value_path().is_none());
    }

    // ── strip_bearer_prefix ──────────────────────────────────────────────────

    #[test]
    fn strip_bearer_prefix_exact() {
        assert_eq!(strip_bearer_prefix("Bearer abc.def.ghi"), Some("abc.def.ghi"));
    }

    #[test]
    fn strip_bearer_prefix_case_insensitive() {
        assert_eq!(strip_bearer_prefix("bearer abc"), Some("abc"));
        assert_eq!(strip_bearer_prefix("BEARER abc"), Some("abc"));
        assert_eq!(strip_bearer_prefix("BeArEr abc"), Some("abc"));
    }

    #[test]
    fn strip_bearer_prefix_multi_whitespace() {
        assert_eq!(strip_bearer_prefix("Bearer   abc"), Some("abc"));
        assert_eq!(strip_bearer_prefix("Bearer\tabc"), Some("abc"));
        assert_eq!(strip_bearer_prefix("  Bearer abc"), Some("abc"));
    }

    #[test]
    fn strip_bearer_prefix_rejects_other_schemes() {
        assert_eq!(strip_bearer_prefix("Basic abc"), None);
        assert_eq!(strip_bearer_prefix("Bearerabc"), None); // no separator
        assert_eq!(strip_bearer_prefix("Bearer "), None);   // empty token
        assert_eq!(strip_bearer_prefix(""), None);
    }

    // ── AuthValuePath helpers ────────────────────────────────────────────────

    #[test]
    fn value_path_falls_back_to_default() {
        let vp = AuthValuePath {
            default: "tenant_id".into(),
            log: None,
            metric_tag: None,
            trace: None,
        };
        assert_eq!(vp.for_log(), "tenant_id");
        assert_eq!(vp.for_metric(), "tenant_id");
        assert_eq!(vp.for_trace(), "tenant_id");
    }

    #[test]
    fn value_path_uses_type_specific_overrides() {
        let vp = AuthValuePath {
            default: "default_field".into(),
            log: Some("log_field".into()),
            metric_tag: Some("metric_key".into()),
            trace: Some("trace_field".into()),
        };
        assert_eq!(vp.for_log(), "log_field");
        assert_eq!(vp.for_metric(), "metric_key");
        assert_eq!(vp.for_trace(), "trace_field");
    }

    // ── AuthorityData serde ──────────────────────────────────────────────────
    //
    // `AuthorityData` is the shared shape used by both `Authority::PublicKey`
    // and `Authority::TlsCert`, so a single set of tests covers both paths.

    #[test]
    fn authority_data_inline_deserializes() {
        let toml = r#"type = "inline"
value = "my-pem-value""#;
        let data: AuthorityData = toml::from_str(toml).unwrap();
        assert!(matches!(data, AuthorityData::Inline { value } if value == "my-pem-value"));
    }

    #[test]
    fn authority_data_file_deserializes() {
        let toml = r#"type = "file"
path = "/etc/certs/auth.pem""#;
        let data: AuthorityData = toml::from_str(toml).unwrap();
        assert!(matches!(data, AuthorityData::File { path } if path == "/etc/certs/auth.pem"));
    }

    #[test]
    fn authority_data_missing_type_fails() {
        assert!(toml::from_str::<AuthorityData>(r#"value = "pem""#).is_err());
    }

    #[test]
    fn authority_data_unknown_type_fails() {
        assert!(toml::from_str::<AuthorityData>(r#"type = "env""#).is_err());
    }

    // ── Authority serde ──────────────────────────────────────────────────────

    #[test]
    fn authority_public_key_deserializes() {
        let toml = r#"pub_key = { type = "inline", value = "pem" }"#;
        let a: Authority = toml::from_str(toml).unwrap();
        assert!(matches!(
            a,
            Authority::PublicKey(AuthorityData::Inline { value }) if value == "pem"
        ));
    }

    #[test]
    fn authority_tls_cert_deserializes() {
        let toml = r#"tls_cert = { type = "file", path = "/etc/pki/tls/certs/auth.crt" }"#;
        let a: Authority = toml::from_str(toml).unwrap();
        assert!(matches!(
            a,
            Authority::TlsCert(AuthorityData::File { path }) if path == "/etc/pki/tls/certs/auth.crt"
        ));
    }

    #[test]
    fn authority_empty_table_fails() {
        // Externally-tagged enum: an empty `[authority]` (no variant key) is
        // not deserializable — this is how we surface "nothing is set".
        assert!(toml::from_str::<Authority>("").is_err());
    }

    #[test]
    fn authority_unknown_variant_fails() {
        let toml = r#"jwks_url = "https://idp.example.com/jwks""#;
        assert!(toml::from_str::<Authority>(toml).is_err());
    }

    #[test]
    fn authority_with_multiple_variants_in_toml_fails() {
        // Externally-tagged enums accept exactly one key. Specifying both
        // `public_key` and `tls_cert` under `[authority]` must be rejected.
        let toml = r#"
pub_key = { type = "inline", value = "pem" }
tls_cert   = { type = "inline", value = "cert" }
"#;
        assert!(toml::from_str::<Authority>(toml).is_err());
    }

    // ── AuthConfig serde ─────────────────────────────────────────────────────

    #[test]
    fn auth_config_requires_authority() {
        // No `[authority]` block at all → missing required field.
        let toml = r#"membership_claim = "site_ids""#;
        assert!(toml::from_str::<AuthConfig>(toml).is_err());
    }

    #[test]
    fn auth_config_with_public_key_authority_deserializes() {
        // Flat form: variant key sits directly under [auth] thanks to
        // #[serde(flatten)] on AuthConfig.authority.
        let toml = r#"
pub_key.type  = "inline"
pub_key.value = "pem"
"#;
        let cfg: AuthConfig = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.authority,
            Authority::PublicKey(AuthorityData::Inline { value }) if value == "pem"
        ));
    }

    #[test]
    fn auth_config_with_tls_cert_authority_deserializes() {
        let toml = r#"
tls_cert.type = "file"
tls_cert.path = "/etc/pki/tls/certs/auth.crt"
"#;
        let cfg: AuthConfig = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.authority,
            Authority::TlsCert(AuthorityData::File { path }) if path == "/etc/pki/tls/certs/auth.crt"
        ));
    }

    #[test]
    fn auth_config_typo_in_sibling_field_is_rejected() {
        // `#[serde(deny_unknown_fields)]` on AuthConfig catches misspellings
        // of any sibling top-level key (here `mempership_claim` →
        // `membership_claim`) at parse time, so the configured value is
        // never silently lost.
        let toml = r#"
pub_key.type  = "inline"
pub_key.value = "pem"
mempership_claim = "tenants"
"#;
        let err = toml::from_str::<AuthConfig>(toml).unwrap_err().to_string();
        assert!(
            err.contains("unknown field `mempership_claim`"),
            "expected `unknown field` error for the typo, got: {err}",
        );
    }

    #[test]
    fn auth_config_typo_in_variant_name_is_rejected() {
        // The variant key itself is misspelled; sibling fields are valid.
        // Authority sees `pubic_key` as an unknown variant and rejects it.
        let toml = r#"
pubic_key.type   = "inline"
pubic_key.value  = "pem"
membership_claim = "tenants"
"#;
        assert!(toml::from_str::<AuthConfig>(toml).is_err());
    }

    // ── deserialize_authority_required error messages ───────────────────────
    //
    // These tests pin the contract of `deserialize_authority_required`:
    // 1. Missing/unrecognized variant key → friendly message naming the
    //    expected keys.
    // 2. Any other deserialization error → original detail preserved with
    //    an `auth.authority:` prefix so the failing field path is unambiguous.

    #[test]
    fn auth_config_missing_authority_variant_gives_friendly_error() {
        // No `pub_key` or `tls_cert` at all — replaces serde's opaque
        // "no variant of enum Authority found in flattened data".
        let toml = r#"membership_claim = "site_ids""#;
        let err = toml::from_str::<AuthConfig>(toml).unwrap_err().to_string();
        assert!(
            err.contains("must set one of `pub_key`, `tls_cert`, or `jwks`"),
            "expected friendly message, got: {err}",
        );
    }

    #[test]
    fn auth_config_typo_in_variant_name_gives_friendly_error() {
        // Typo'd variant key (`pubic_key`) is indistinguishable from
        // "no variant set" at the flatten layer, so the friendly fallback
        // fires here too.
        let toml = r#"
pubic_key.type  = "inline"
pubic_key.value = "pem"
"#;
        let err = toml::from_str::<AuthConfig>(toml).unwrap_err().to_string();
        assert!(
            err.contains("must set one of `pub_key`, `tls_cert`, or `jwks`"),
            "expected friendly message, got: {err}",
        );
    }

    #[test]
    fn auth_config_bad_type_value_gets_authority_prefix() {
        // Variant key is correct; the inner `type` discriminator is
        // unknown. The original serde "unknown variant" message must
        // survive — only prefixed with the field path.
        let toml = r#"
pub_key.type  = "env"
pub_key.value = "pem"
"#;
        let err = toml::from_str::<AuthConfig>(toml).unwrap_err().to_string();
        assert!(
            err.contains("auth.authority:"),
            "expected `auth.authority:` prefix, got: {err}",
        );
        assert!(
            err.contains("env"),
            "expected the bad variant name in the message, got: {err}",
        );
    }

    #[test]
    fn auth_config_inner_field_typo_gets_authority_prefix() {
        // Variant resolves, but `deny_unknown_fields` on AuthorityData
        // rejects the misspelled `paht`. Want the `auth.authority:` prefix
        // in front of serde's "unknown field" detail.
        let toml = r#"
pub_key.type = "file"
pub_key.paht = "/etc/key.pem"
"#;
        let err = toml::from_str::<AuthConfig>(toml).unwrap_err().to_string();
        assert!(
            err.contains("auth.authority:"),
            "expected `auth.authority:` prefix, got: {err}",
        );
        assert!(
            err.contains("paht"),
            "expected the typo'd field name in the message, got: {err}",
        );
    }

    #[test]
    fn auth_config_with_other_fields_alongside_variant_deserializes() {
        // Confirms the flatten machinery doesn't get confused by sibling
        // top-level fields — `issuer`, `membership_claim` etc. coexist with
        // the flattened variant key.
        let toml = r#"
pub_key.type   = "inline"
pub_key.value  = "pem"
membership_claim  = "tenants"
issuer            = "https://issuer.example.com/"
"#;
        let cfg: AuthConfig = toml::from_str(toml).unwrap();
        assert!(matches!(
            cfg.authority,
            Authority::PublicKey(AuthorityData::Inline { value }) if value == "pem"
        ));
        assert_eq!(cfg.membership_claim, Some(MembershipClaimConfig::Identity("tenants".to_string())));
        assert_eq!(cfg.issuer.as_deref(), Some("https://issuer.example.com/"));
    }

    // ── MembershipClaimConfig serde ──────────────────────────────────────────

    #[test]
    fn membership_claim_config_plain_string_deserializes_as_identity() {
        let toml = r#"
pub_key.type  = "inline"
pub_key.value = "pem"
membership_claim = "site_ids"
"#;
        let cfg: AuthConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.membership_claim,
            Some(MembershipClaimConfig::Identity("site_ids".to_string())),
        );
    }

    #[test]
    fn membership_claim_config_inline_table_deserializes_as_regexp() {
        let toml = r#"
pub_key.type  = "inline"
pub_key.value = "pem"
membership_claim = { claim = "roles", pattern = "^tenant:[^:]+$" }
"#;
        let cfg: AuthConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.membership_claim,
            Some(MembershipClaimConfig::Regexp {
                claim: "roles".to_string(),
                pattern: "^tenant:[^:]+$".to_string(),
            }),
        );
    }

    #[test]
    fn membership_claim_config_section_table_deserializes_as_regexp() {
        let toml = r#"
pub_key.type       = "inline"
pub_key.value      = "pem"
membership_claim.claim   = "roles"
membership_claim.pattern = "^tenant:.+"
"#;
        let cfg: AuthConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.membership_claim,
            Some(MembershipClaimConfig::Regexp {
                claim: "roles".to_string(),
                pattern: "^tenant:.+".to_string(),
            }),
        );
    }

    #[test]
    fn membership_claim_config_absent_means_none() {
        let toml = r#"
pub_key.type  = "inline"
pub_key.value = "pem"
"#;
        let cfg: AuthConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.membership_claim, None);
    }

    // ── MembershipClaim::extract ────────────────────────────────────────

    #[test]
    fn extract_identity_returns_all_string_values() {
        let claim = MembershipClaim::Identity("ids".to_string());
        let mut claims = serde_json::Map::new();
        claims.insert("ids".into(), serde_json::json!(["alpha", "beta"]));
        let set = claim.extract(&claims).unwrap();
        let expected: BTreeSet<String> = ["alpha", "beta"].iter().map(|s| s.to_string()).collect();
        assert_eq!(set, expected);
    }

    #[test]
    fn extract_identity_skips_non_string_elements() {
        // Mixed array: string elements are collected; non-strings are dropped.
        let claim = MembershipClaim::Identity("ids".to_string());
        let mut claims = serde_json::Map::new();
        claims.insert("ids".into(), serde_json::json!(["alpha", 42, null, "beta"]));
        let set = claim.extract(&claims).unwrap();
        let expected: BTreeSet<String> = ["alpha", "beta"].iter().map(|s| s.to_string()).collect();
        assert_eq!(set, expected);
    }

    #[test]
    fn extract_identity_all_non_string_elements_is_error() {
        // Array with no string elements yields an empty set — treat as missing claim.
        let claim = MembershipClaim::Identity("ids".to_string());
        let mut claims = serde_json::Map::new();
        claims.insert("ids".into(), serde_json::json!([42, null, true]));
        assert!(matches!(
            claim.extract(&claims),
            Err(AuthError::InvalidToken(_)),
        ));
    }

    #[test]
    fn extract_identity_empty_array_is_error() {
        // An empty array yields no membership values — treat as missing claim.
        let claim = MembershipClaim::Identity("ids".to_string());
        let mut claims = serde_json::Map::new();
        claims.insert("ids".into(), serde_json::json!([]));
        assert!(matches!(
            claim.extract(&claims),
            Err(AuthError::InvalidToken(_)),
        ));
    }

    #[test]
    fn extract_identity_missing_claim_is_error() {
        let claim = MembershipClaim::Identity("ids".to_string());
        let claims = serde_json::Map::new();
        assert!(matches!(
            claim.extract(&claims),
            Err(AuthError::InvalidToken(_)),
        ));
    }

    #[test]
    fn extract_identity_non_array_claim_is_error() {
        // Identity always expects a JSON array — a plain string is rejected.
        let claim = MembershipClaim::Identity("ids".to_string());
        let mut claims = serde_json::Map::new();
        claims.insert("ids".into(), serde_json::json!("not-an-array"));
        assert!(matches!(
            claim.extract(&claims),
            Err(AuthError::InvalidToken(_)),
        ));
    }

    #[test]
    fn extract_regexp_returns_all_capture_groups() {
        // Pattern has two capture groups; both enter the set.
        // The full match (group 0) is excluded.
        let re = Regex::new(r"^(tenant)_([0-9]+)@example\.com$").unwrap();
        let claim = MembershipClaim::Regexp("email".to_string(), re);
        let mut claims = serde_json::Map::new();
        claims.insert("email".into(), serde_json::json!("tenant_42@example.com"));
        let set = claim.extract(&claims).unwrap();
        let expected: BTreeSet<String> = ["tenant", "42"].iter().map(|s| s.to_string()).collect();
        assert_eq!(set, expected);
    }

    #[test]
    fn extract_regexp_single_capture_group_email_claim() {
        // Pattern extracts the numeric tenant ID from an email-style claim.
        let re = Regex::new(r"^tenant_([0-9]+)@example\.com$").unwrap();
        let claim = MembershipClaim::Regexp("email".to_string(), re);
        let mut claims = serde_json::Map::new();
        claims.insert("email".into(), serde_json::json!("tenant_42@example.com"));
        let set = claim.extract(&claims).unwrap();
        let expected: BTreeSet<String> = ["42"].iter().map(|s| s.to_string()).collect();
        assert_eq!(set, expected);
    }

    #[test]
    fn extract_regexp_partial_capture_excludes_prefix() {
        // ^tenant_([0-9]+)$ on "tenant_1" captures only the digits "1",
        // not the full string "tenant_1". Use ^(tenant_[0-9]+)$ to keep the prefix.
        let re = Regex::new(r"^tenant_([0-9]+)$").unwrap();
        let claim = MembershipClaim::Regexp("sub".to_string(), re);
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("tenant_1"));
        let set = claim.extract(&claims).unwrap();
        assert_eq!(set, ["1"].iter().map(|s| s.to_string()).collect::<BTreeSet<_>>());
        assert!(!set.contains("tenant_1"));
    }

    #[test]
    fn extract_regexp_whole_value_capture() {
        // Wrapping the full pattern in a capture group preserves the complete value.
        let re = Regex::new(r"^(tenant_[0-9]+)$").unwrap();
        let claim = MembershipClaim::Regexp("sub".to_string(), re);
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("tenant_1"));
        let set = claim.extract(&claims).unwrap();
        assert_eq!(set, ["tenant_1"].iter().map(|s| s.to_string()).collect::<BTreeSet<_>>());
    }

    #[test]
    fn extract_regexp_no_match_is_error() {
        let re = Regex::new(r"^tenant_([0-9]+)@example\.com$").unwrap();
        let claim = MembershipClaim::Regexp("email".to_string(), re);
        let mut claims = serde_json::Map::new();
        claims.insert("email".into(), serde_json::json!("admin@example.com"));
        assert!(matches!(
            claim.extract(&claims),
            Err(AuthError::InvalidToken(_)),
        ));
    }

    #[test]
    fn extract_regexp_array_claim_is_error() {
        // Regexp expects a scalar string claim, not an array.
        let re = Regex::new(r"^tenant_([0-9]+)$").unwrap();
        let claim = MembershipClaim::Regexp("ids".to_string(), re);
        let mut claims = serde_json::Map::new();
        claims.insert("ids".into(), serde_json::json!(["tenant_1", "tenant_2"]));
        assert!(matches!(
            claim.extract(&claims),
            Err(AuthError::InvalidToken(_)),
        ));
    }

    #[test]
    fn extract_regexp_missing_claim_is_error() {
        let re = Regex::new(r".*").unwrap();
        let claim = MembershipClaim::Regexp("roles".to_string(), re);
        let claims = serde_json::Map::new();
        assert!(matches!(
            claim.extract(&claims),
            Err(AuthError::InvalidToken(_)),
        ));
    }

    #[test]
    fn extract_regexp_all_optional_groups_unmatched_is_error() {
        // Pattern matches but all capture groups are optional and none fired —
        // the resulting set would be empty, so this is treated as missing claim.
        let re = Regex::new(r"^value(?:-(foo))?(?:-(bar))?$").unwrap();
        let claim = MembershipClaim::Regexp("role".to_string(), re);
        let mut claims = serde_json::Map::new();
        // Matches the outer pattern but neither optional group fires.
        claims.insert("role".into(), serde_json::json!("value"));
        assert!(matches!(
            claim.extract(&claims),
            Err(AuthError::InvalidToken(_)),
        ));
    }

    // ── JWKS / Keycloak authority ────────────────────────────────────────────

    const TEST_KID: &str = "test-kid";

    /// Build a single-entry JWKS JSON from the test public key.
    ///
    /// When `include_alg` is false the `alg` field is omitted, matching the
    /// Auth0 behaviour when "Include Signing Algorithms in JSON Web Key Set"
    /// is toggled off in the tenant advanced settings.
    fn make_jwks_json_full(kid: &str, use_sig: bool, include_alg: bool) -> serde_json::Value {
        use base64::Engine;
        use openssl::rsa::Rsa;

        let rsa = Rsa::public_key_from_pem(TEST_PUBLIC_KEY.as_bytes()).unwrap();
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec());
        let use_field = if use_sig { "sig" } else { "enc" };
        let mut key = serde_json::json!({
            "kid": kid,
            "kty": "RSA",
            "use": use_field,
            "n": n,
            "e": e,
        });
        if include_alg {
            key["alg"] = serde_json::json!("RS256");
        }
        serde_json::json!({ "keys": [key] })
    }

    fn make_jwks_json(kid: &str, use_sig: bool) -> serde_json::Value {
        make_jwks_json_full(kid, use_sig, true)
    }

    /// Mint a JWT signed by the test private key with an explicit `kid`.
    fn make_token_with_kid(kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("test-subject"));
        claims.insert("exp".into(), serde_json::json!(now_secs() + 3600));
        claims.insert("site_ids".into(), serde_json::json!(["site-123"]));
        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    fn jwks_cfg(jwks_url: String) -> AuthConfig {
        AuthConfig {
            authority: Authority::Jwks(JwksAuthority {
                jwks_url,
                refresh_interval_secs: 3600, // long; periodic refresh shouldn't fire during test
                fetch_timeout_secs: 5,
                min_reactive_refresh_secs: 0, // allow reactive refresh without cooldown wait
            }),
            issuer: None,
            audience: None,
            membership_claim: Some(MembershipClaimConfig::Identity("site_ids".to_string())),
            value_path: None,
            algorithms: None,
        }
    }

    /// Generate a fresh P-256 key pair and return (jwks_json, encoding_key).
    ///
    /// jsonwebtoken requires PKCS8 PEM (`BEGIN PRIVATE KEY`) for EC keys —
    /// SEC1 (`BEGIN EC PRIVATE KEY`) is not accepted.
    fn make_ec_p256_test_key(kid: &str) -> (serde_json::Value, EncodingKey) {
        use base64::Engine;
        use openssl::bn::{BigNum, BigNumContext};
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();

        let mut ctx = BigNumContext::new().unwrap();
        let mut x_bn = BigNum::new().unwrap();
        let mut y_bn = BigNum::new().unwrap();
        key.public_key()
            .affine_coordinates_gfp(&group, &mut x_bn, &mut y_bn, &mut ctx)
            .unwrap();

        // P-256 coordinates must be exactly 32 bytes; pad with leading zeros.
        let encode_coord = |bn: &BigNum| {
            let bytes = bn.to_vec();
            let mut padded = vec![0u8; 32usize.saturating_sub(bytes.len())];
            padded.extend_from_slice(&bytes);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&padded)
        };

        let jwks = serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "use": "sig",
                "alg": "ES256",
                "kid": kid,
                "x": encode_coord(&x_bn),
                "y": encode_coord(&y_bn),
            }]
        });

        let pkey = PKey::from_ec_key(key).unwrap();
        let pem = pkey.private_key_to_pem_pkcs8().unwrap();
        let encoding_key = EncodingKey::from_ec_pem(&pem).unwrap();

        (jwks, encoding_key)
    }

    fn make_ec_token_with_kid(kid: &str, encoding_key: &EncodingKey) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("test-subject"));
        claims.insert("exp".into(), serde_json::json!(now_secs() + 3600));
        claims.insert("site_ids".into(), serde_json::json!(["site-123"]));
        encode(&header, &claims, encoding_key).unwrap()
    }

    #[tokio::test]
    async fn jwks_build_succeeds_with_mock_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        let cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        assert!(cfg.build().await.is_ok());
    }

    #[tokio::test]
    async fn jwks_build_fails_when_endpoint_unreachable() {
        // Port 1 is reserved and refuses connections — guaranteed failure
        // without depending on a mock server lifecycle.
        let cfg = jwks_cfg("http://127.0.0.1:1/jwks".to_string());
        let err = cfg.build().await.unwrap_err().to_string();
        assert!(
            err.contains("initial fetch") && err.contains("failed"),
            "got: {err}",
        );
    }

    #[tokio::test]
    async fn jwks_build_fails_when_endpoint_returns_no_signing_keys() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"keys": []})))
            .mount(&server)
            .await;

        let cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        let err = cfg.build().await.unwrap_err().to_string();
        assert!(err.contains("no usable signing keys"), "got: {err}");
    }

    #[tokio::test]
    async fn jwks_authenticate_valid_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        let token = make_token_with_kid(TEST_KID);
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    #[tokio::test]
    async fn jwks_authenticate_unknown_kid_triggers_refresh() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // First two fetches (initial build + the unknown-kid token will come
        // before any refresh fires) return a JWKS with the WRONG kid. The
        // third onwards (reactive refresh after unknown-kid) returns the
        // correct one.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json("stale-kid", true)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        let token = make_token_with_kid(TEST_KID);
        // First authenticate: initial cache has stale-kid only; unknown-kid
        // miss triggers reactive refresh which fetches the corrected JWKS.
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    /// When the reactive refresh fires but the IdP still does not publish the
    /// requested `kid`, the slow path must return `InvalidToken("unknown signing
    /// key")` rather than panic or loop.
    #[tokio::test]
    async fn jwks_unknown_kid_after_refresh_is_rejected() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Both the initial fetch and every subsequent refresh return only
        // "other-kid" — the token's kid is never published.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(make_jwks_json("other-kid", true)),
            )
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        let token = make_token_with_kid("never-published-kid");
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    /// The cooldown gate suppresses a *second* reactive refresh that arrives
    /// within the cooldown window. The first unknown-kid request after startup
    /// always triggers a refresh (startup initialises the cooldown clock to
    /// "already elapsed"). Only subsequent requests within the window are gated.
    #[tokio::test]
    async fn jwks_reactive_refresh_skipped_within_cooldown() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // The JWKS never contains "never-published-kid", so every reactive
        // refresh still leaves the cache without the requested kid.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json("stale-kid", true)))
            .mount(&server)
            .await;

        // 60-second cooldown — expires only once (right at startup), then gates
        // further requests for 60 s.
        let mut cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        if let Authority::Jwks(ref mut j) = cfg.authority {
            j.min_reactive_refresh_secs = 60;
        }
        let auth = cfg.build().await.unwrap();

        let token = make_token_with_kid("never-published-kid");

        // First request: cooldown has already elapsed at startup, so a reactive
        // refresh fires — total requests = 2 (build + reactive).
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "first unknown-kid request must trigger a reactive refresh"
        );

        // Second request immediately after: cooldown now in effect — no fetch.
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "reactive refresh must be suppressed within the cooldown window"
        );
    }

    #[tokio::test]
    async fn jwks_token_without_kid_is_rejected() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        // Mint a kid-less token directly (helper that adds kid bypassed).
        let token = make_token(HashMap::new());
        let result = auth.authenticate(Some(&bearer(&token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    /// The JWKS authenticate path calls `decode_header` explicitly before any
    /// key lookup to extract the `kid`. A token with a malformed header must be
    /// rejected before the cache is consulted — not confused with an expired or
    /// bad-signature error. This code path is distinct from the static-PEM path
    /// which calls `decode` directly.
    #[tokio::test]
    async fn jwks_malformed_token_header_rejected() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        // "not.a.jwt" has three segments but the header part ("not") is not
        // valid base64url JSON — `decode_header` will fail before any key lookup.
        let result = auth.authenticate(Some("Bearer not.a.jwt")).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
        // No reactive refresh should have been triggered.
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn jwks_skips_use_enc_entries() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Only a use=enc entry — must be filtered out, leaving an empty key
        // map which the build() rejects with "no usable signing keys".
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, false)))
            .mount(&server)
            .await;

        let cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        let err = cfg.build().await.unwrap_err().to_string();
        assert!(err.contains("no usable signing keys"), "got: {err}");
    }

    /// A JWK entry without a `kid` field cannot be looked up per-token (we
    /// index by kid) and must be skipped with a warning. Other valid entries in
    /// the same response must still be indexed and usable for authentication.
    #[tokio::test]
    async fn jwks_kidless_entry_skipped_other_keys_still_indexed() {
        use base64::Engine;
        use openssl::rsa::Rsa;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rsa = Rsa::public_key_from_pem(TEST_PUBLIC_KEY.as_bytes()).unwrap();
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec());

        let jwks = serde_json::json!({
            "keys": [
                // Entry without `kid` — must be skipped.
                { "kty": "RSA", "use": "sig", "alg": "RS256", "n": n, "e": e },
                // Entry with `kid` — must be indexed.
                { "kid": TEST_KID, "kty": "RSA", "use": "sig", "alg": "RS256", "n": n, "e": e },
            ]
        });

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;

        // Build must succeed despite the kid-less entry.
        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();

        // Token signed with the keyed entry must authenticate.
        let token = make_token_with_kid(TEST_KID);
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    // ── EC key (ES256 / ES384) tests ─────────────────────────────────────────

    /// EC-only JWKS is accepted without any `algorithms` config — the JWKS
    /// endpoint is the authority on which key types are valid.
    #[tokio::test]
    async fn jwks_ec_only_accepted_without_algorithm_config() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let (ec_jwks, ec_enc_key) = make_ec_p256_test_key(TEST_KID);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ec_jwks))
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        let token = make_ec_token_with_kid(TEST_KID, &ec_enc_key);
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    /// Setting `algorithms` alongside `jwks` authority is a configuration error —
    /// the JWKS endpoint is self-describing and no algorithm config is needed.
    #[tokio::test]
    async fn jwks_algorithms_field_is_config_error() {
        let mut cfg = jwks_cfg("http://unused/jwks".to_string());
        cfg.algorithms = Some(vec![AuthAlgorithm::Rs256]);
        let err = cfg.build().await.unwrap_err().to_string();
        assert!(err.contains("not applicable with"), "got: {err}");
    }

    /// A JWKS with both RSA and EC keys validates tokens for each key type
    /// independently — no algorithm configuration required.
    #[tokio::test]
    async fn jwks_mixed_rsa_and_ec_keys_both_validate() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let ec_kid = "ec-key";

        let rsa_entry = make_jwks_json(TEST_KID, true)["keys"][0].clone();
        let (ec_jwks_single, ec_enc_key) = make_ec_p256_test_key(ec_kid);
        let ec_entry = ec_jwks_single["keys"][0].clone();
        let combined = serde_json::json!({"keys": [rsa_entry, ec_entry]});

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(combined))
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();

        // RSA-signed token (kid = TEST_KID).
        let rsa_token = make_token_with_kid(TEST_KID);
        let ctx = auth.authenticate(Some(&bearer(&rsa_token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));

        // EC-signed token (kid = ec_kid).
        let ec_token = make_ec_token_with_kid(ec_kid, &ec_enc_key);
        let ctx = auth.authenticate(Some(&bearer(&ec_token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    // ── IdP compatibility tests ───────────────────────────────────────────────

    /// Auth0 allows administrators to disable "Include Signing Algorithms in
    /// JSON Web Key Set", which removes the `alg` field from every JWK entry.
    /// Keys without an `alg` must still be accepted and must validate tokens.
    #[tokio::test]
    async fn jwks_auth0_key_without_alg_field_is_accepted() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(make_jwks_json_full(TEST_KID, true, false)),
            )
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        let token = make_token_with_kid(TEST_KID);
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    /// Keycloak publishes both a `use=sig` signing key and a `use=enc`
    /// encryption key in the same JWKS response. Only the signing key must
    /// enter the cache; the encryption key must be silently skipped.
    #[tokio::test]
    async fn jwks_keycloak_enc_key_alongside_sig_key_is_filtered() {
        use base64::Engine;
        use openssl::rsa::Rsa;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rsa = Rsa::public_key_from_pem(TEST_PUBLIC_KEY.as_bytes()).unwrap();
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec());

        // Keycloak-style response: one sig key + one enc key, same RSA material.
        let jwks = serde_json::json!({
            "keys": [
                { "kid": TEST_KID, "kty": "RSA", "use": "sig", "alg": "RS256", "n": n, "e": e },
                { "kid": "enc-key", "kty": "RSA", "use": "enc", "alg": "RSA-OAEP", "n": n, "e": e },
            ]
        });

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;

        let auth = jwks_cfg(format!("{}/jwks", server.uri())).build().await.unwrap();
        let token = make_token_with_kid(TEST_KID);
        // Token signed with the sig key must validate.
        let ctx = auth.authenticate(Some(&bearer(&token))).await.unwrap().unwrap();
        assert!(ctx.is_authorized("site-123"));
        // Token claiming the enc kid must be rejected (enc key not in cache).
        let enc_token = make_token_with_kid("enc-key");
        let result = auth.authenticate(Some(&bearer(&enc_token))).await;
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    // ── periodic-refresh tests ───────────────────────────────────────────────

    /// The background refresher must atomically swap in a new key map when the
    /// periodic interval fires. A key that was absent at build time must become
    /// usable after the refresh without any reactive (on-unknown-kid) fetch.
    ///
    /// Pinning `min_reactive_refresh_secs` to a large value ensures that the
    /// key becomes available only through the periodic path, not the reactive
    /// one. The test waits 1.5× the refresh interval for the task to fire.
    #[tokio::test(flavor = "multi_thread")]
    async fn jwks_periodic_refresh_rotates_keys() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Initial fetch: only "old-kid".
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json("old-kid", true)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Periodic refresh onwards: only TEST_KID (old-kid has been rotated out).
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        let mut cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        if let Authority::Jwks(ref mut j) = cfg.authority {
            j.refresh_interval_secs = 1;
            j.min_reactive_refresh_secs = 0; // reactive refresh allowed immediately
        }
        let auth = cfg.build().await.unwrap();

        // old-kid is in the initial cache — tokens signed by it must work.
        let old_token = make_token_with_kid("old-kid");
        assert!(
            auth.authenticate(Some(&bearer(&old_token))).await.is_ok(),
            "old-kid should be valid before periodic rotation"
        );

        // Wait for the periodic refresh (1 s interval + 500 ms buffer).
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // After the background swap old-kid has been removed; TEST_KID is now the only key.
        assert!(
            auth.authenticate(Some(&bearer(&old_token))).await.is_err(),
            "old-kid should be invalid after periodic rotation"
        );
        let new_token = make_token_with_kid(TEST_KID);
        let ctx = auth
            .authenticate(Some(&bearer(&new_token)))
            .await
            .unwrap()
            .unwrap();
        assert!(ctx.is_authorized("site-123"));
    }

    // ── concurrent / race-condition tests ────────────────────────────────────

    /// N concurrent requests with an unknown `kid` must trigger exactly ONE
    /// reactive HTTP fetch, not N. The cooldown gate (`min_reactive_refresh_secs`)
    /// must hold under real concurrency — the timestamp is stamped inside the
    /// mutex before the fetch begins so racing callers see it and bail out.
    ///
    /// Note: the startup clock is pre-wound so the first reactive refresh is
    /// always allowed. We use `min_reactive_refresh_secs = 1` and sleep past it
    /// so the gate is open when the concurrent calls race, but any second wave
    /// within 1 s would be suppressed.
    #[tokio::test(flavor = "multi_thread")]
    async fn jwks_concurrent_unknown_kid_triggers_exactly_one_refresh() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // First fetch (initial build): stale-kid only.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json("stale-kid", true)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // All subsequent fetches return the correct kid.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(TEST_KID, true)))
            .mount(&server)
            .await;

        // 1-second cooldown — short enough to expire in the test, non-zero so
        // the gate logic is actually exercised by the concurrent callers.
        let mut cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        if let Authority::Jwks(ref mut j) = cfg.authority {
            j.min_reactive_refresh_secs = 1;
        }
        let auth = cfg.build().await.unwrap();

        // Sleep past the cooldown window so it is open when the 20 requests race.
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let token = make_token_with_kid(TEST_KID);

        // Spawn 20 concurrent authenticate calls, all with the unknown kid.
        let mut handles = Vec::new();
        for _ in 0..20 {
            let auth = auth.clone();
            let bearer = bearer(&token);
            handles.push(tokio::spawn(async move {
                // Result is intentionally ignored — we only care about HTTP call count.
                let _ = auth.authenticate(Some(&bearer)).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // Exactly 2 HTTP calls: 1 initial build + 1 reactive refresh.
        // The Mutex gate ensures only the first caller past the cooldown
        // fires a fetch; the remaining 19 see the freshly-stamped timestamp
        // and return early without issuing their own requests.
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "expected exactly 1 initial + 1 reactive fetch; cooldown gate failed to suppress duplicates"
        );
    }

    /// Concurrent readers must all see a consistent key map — either the old
    /// snapshot or the new one — never a partially-written state. Spawn many
    /// readers while a refresh is swapping in a new key map and assert that
    /// every reader either validates correctly or gets a clean "unknown key"
    /// error; no panics, no partial reads.
    #[tokio::test(flavor = "multi_thread")]
    async fn jwks_concurrent_readers_see_consistent_snapshot_during_swap() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Alternate between two valid key sets on successive fetches so that
        // the periodic refresher swaps the map while readers are running.
        let kid_a = "kid-a";
        let kid_b = "kid-b";

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(kid_a, true)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_jwks_json(kid_b, true)))
            .mount(&server)
            .await;

        // Very short periodic refresh so it fires during the test.
        let mut cfg = jwks_cfg(format!("{}/jwks", server.uri()));
        if let Authority::Jwks(ref mut j) = cfg.authority {
            j.refresh_interval_secs = 1;
            j.min_reactive_refresh_secs = 0;
        }
        let auth = cfg.build().await.unwrap();

        // Token for kid_a (in the initial cache).
        let token_a = make_token_with_kid(kid_a);
        // Token for kid_b (arrives after the swap).
        let token_b = make_token_with_kid(kid_b);

        // Hammer with 50 concurrent readers across both kids for ~1.5 seconds,
        // spanning at least one periodic swap. Every result must be either a
        // clean Ok or a clean InvalidToken — no panics, no corrupted state.
        let mut handles = Vec::new();
        for i in 0..50 {
            let auth = auth.clone();
            let token = if i % 2 == 0 { token_a.clone() } else { token_b.clone() };
            handles.push(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(i * 30)).await;
                let bearer = bearer(&token);
                // Must be Ok or InvalidToken — no panic, no partial read.
                let _ = auth.authenticate(Some(&bearer)).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }
}
