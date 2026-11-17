use std::time::Duration;

use serde_with::serde_as;
use vector_lib::configurable::configurable_component;
use vector_lib::sensitive_string::SensitiveString;

const fn default_reload_interval() -> Duration {
    Duration::from_secs(2)
}

/// Source of an auth bearer token sent with outgoing requests.
///
/// Exactly one variant must be configured.
///
/// ## Examples
///
/// Inline value (use Vector's `${VAR}` interpolation for env vars):
/// ```toml
/// token.type  = "inline"
/// token.value = "${MY_AUTH_TOKEN}"
/// ```
///
/// File path (re-read at most every `reload_interval` for Kubernetes secret rotation):
/// ```toml
/// token.type = "file"
/// token.path = "/var/run/secrets/vector/token"
/// ```
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum AuthTokenConfig {
    /// Inline token value.
    ///
    /// Supports Vector's `${ENV_VAR}` interpolation. The value is resolved once at
    /// config load time.
    Inline {
        /// Bearer token value.
        value: SensitiveString,
    },

    /// Path to a file containing the bearer token.
    ///
    /// The file is re-read when a request needs the token and `reload_interval` has
    /// passed since the last read, so that a rotated Kubernetes secret volume mount is
    /// picked up automatically without restarting the agent or touching the
    /// filesystem on every request.
    File {
        /// Path to the token file.
        path: String,

        /// Minimum time between reads of the token file.
        #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
        #[serde(default = "default_reload_interval", alias = "reload_interval_secs")]
        #[configurable(metadata(docs::human_name = "Reload Interval"))]
        reload_interval: Duration,
    },
}

/// Pre-parsed auth state built once at sink construction time.
///
/// For inline tokens the `Authorization` header value is pre-formatted into a
/// `MetadataValue` so the hot request path pays no allocation or parse cost.
#[cfg(any(feature = "sinks-vector", feature = "sources-bsp"))]
#[derive(Debug)]
pub struct AuthState {
    token: AuthToken,
}

#[cfg(any(feature = "sinks-vector", feature = "sources-bsp"))]
#[derive(Debug)]
pub enum AuthToken {
    /// Fully-formatted `"Bearer <value>"` ready to insert into gRPC metadata.
    Static(tonic::metadata::MetadataValue<tonic::metadata::Ascii>),
    /// Token file re-read at most every `reload_interval` (K8s secret rotation).
    File(FileToken),
}

#[cfg(any(feature = "sinks-vector", feature = "sources-bsp"))]
#[derive(Debug)]
pub struct FileToken {
    path: String,
    reload_interval: Duration,
    /// The last read and when it happened, locked only to copy it out. Failed reads are
    /// kept too, so a missing file costs one filesystem call per interval rather than
    /// one per request.
    last_read: std::sync::Mutex<Option<LastRead>>,
    /// Held by the one caller re-reading the file. Others serve `last_read` meanwhile
    /// instead of waiting.
    reloading: std::sync::Mutex<()>,
}

#[cfg(any(feature = "sinks-vector", feature = "sources-bsp"))]
#[derive(Clone, Debug)]
struct LastRead {
    at: std::time::Instant,
    read: TokenRead,
}

#[cfg(any(feature = "sinks-vector", feature = "sources-bsp"))]
type TokenRead = Result<tonic::metadata::MetadataValue<tonic::metadata::Ascii>, String>;

#[cfg(any(feature = "sinks-vector", feature = "sources-bsp"))]
impl FileToken {
    const fn new(path: String, reload_interval: Duration) -> Self {
        Self {
            path,
            reload_interval,
            last_read: std::sync::Mutex::new(None),
            reloading: std::sync::Mutex::new(()),
        }
    }

    fn last(&self) -> Option<LastRead> {
        self.last_read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn fresh(&self) -> Option<TokenRead> {
        self.last()
            .filter(|last| last.at.elapsed() < self.reload_interval)
            .map(|last| last.read)
    }

    fn bearer_token(&self) -> TokenRead {
        match self.fresh() {
            Some(read) => read,
            None => match self.reloading.try_lock() {
                Ok(_reloading) => self.reload(),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    let _reloading = poisoned.into_inner();
                    self.reload()
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    match self.last() {
                        Some(stale) => stale.read,
                        // Nothing to serve yet: wait for the read in progress.
                        None => {
                            let _reloading = self
                                .reloading
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            self.reload()
                        }
                    }
                }
            },
        }
    }

    /// Called with `reloading` held.
    fn reload(&self) -> TokenRead {
        // Another caller may have finished a read while this one waited for the lock.
        self.fresh().unwrap_or_else(|| {
            let read = self.read();
            *self
                .last_read
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(LastRead {
                at: std::time::Instant::now(),
                read: read.clone(),
            });
            read
        })
    }

    fn read(&self) -> TokenRead {
        let raw = std::fs::read_to_string(&self.path)
            .map_err(|err| format!("failed to read token file '{}': {err}", self.path))?;
        let token = raw.trim();
        format!("Bearer {token}")
            .parse::<tonic::metadata::MetadataValue<_>>()
            .map_err(|err| format!("token file contains invalid characters: {err}"))
    }
}

#[cfg(any(feature = "sinks-vector", feature = "sources-bsp"))]
impl AuthState {
    /// Builds an `AuthState` from an [`AuthTokenConfig`].
    ///
    /// For inline tokens the value is parsed into [`tonic::metadata::MetadataValue`]
    /// here — once at construction — so the hot request path has no parse work to do.
    ///
    /// Returns a `&'static str` error message on failure; the caller is responsible
    /// for converting it to the appropriate error type.
    pub fn from_config(token: AuthTokenConfig) -> Result<Self, &'static str> {
        let token = match token {
            AuthTokenConfig::Inline { value } => {
                let header = format!("Bearer {}", value.inner())
                    .parse()
                    .map_err(|_| "auth token (inline) contains characters invalid for gRPC metadata")?;
                AuthToken::Static(header)
            }
            AuthTokenConfig::File {
                path,
                reload_interval,
            } => AuthToken::File(FileToken::new(path, reload_interval)),
        };

        Ok(Self { token })
    }

    /// Returns the current bearer token as a gRPC `MetadataValue`.
    ///
    /// For [`AuthToken::Static`] this is a cheap clone of the pre-built value.
    /// For [`AuthToken::File`] the token file is re-read once `reload_interval` has
    /// passed since the last read, so that a rotated Kubernetes secret is picked up
    /// without restarting the agent.
    ///
    /// Returns an error message string on failure; the caller is responsible for
    /// converting it to the appropriate error type.
    pub fn bearer_token(
        &self,
    ) -> Result<tonic::metadata::MetadataValue<tonic::metadata::Ascii>, String> {
        match &self.token {
            AuthToken::Static(value) => Ok(value.clone()),
            AuthToken::File(file) => file.bearer_token(),
        }
    }
}

#[cfg(all(test, feature = "sinks-vector"))]
mod tests {
    use std::io::Write;

    use super::*;

    // -- from_config --

    #[test]
    fn from_config_inline_builds_correctly() {
        let state = AuthState::from_config(AuthTokenConfig::Inline {
            value: "my-auth-token".to_string().into(),
        })
        .expect("valid inline config should build");

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer my-auth-token"
        );
    }

    #[test]
    fn from_config_file_stores_path() {
        let state = AuthState::from_config(AuthTokenConfig::File {
            path: "/some/path/token".into(),
            reload_interval: Duration::ZERO,
        })
        .expect("valid file config should build");

        // Construction succeeds without reading the file.
        assert!(matches!(state.token, AuthToken::File(_)));
    }

    #[test]
    fn from_config_inline_invalid_token_returns_error() {
        let result = AuthState::from_config(AuthTokenConfig::Inline {
            value: "bad\0token".to_string().into(),
        });
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("auth token (inline) contains characters invalid"));
    }

    // -- bearer_token --

    #[test]
    fn bearer_token_inline_is_cheap_clone() {
        let state = AuthState::from_config(AuthTokenConfig::Inline {
            value: "tok".to_string().into(),
        })
        .unwrap();

        // Both calls return the same value without I/O.
        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            state.bearer_token().unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn bearer_token_file_reads_content() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "my-rotating-token").unwrap();

        let state = AuthState::from_config(AuthTokenConfig::File {
            path: f.path().to_str().unwrap().into(),
            reload_interval: Duration::ZERO,
        })
        .unwrap();

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer my-rotating-token"
        );
    }

    #[test]
    fn bearer_token_file_trims_trailing_whitespace() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "token-with-newline\n").unwrap();

        let state = AuthState::from_config(AuthTokenConfig::File {
            path: f.path().to_str().unwrap().into(),
            reload_interval: Duration::ZERO,
        })
        .unwrap();

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer token-with-newline"
        );
    }

    #[test]
    fn bearer_token_file_rotation_reflected_on_next_call() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "original-token").unwrap();

        let state = AuthState::from_config(AuthTokenConfig::File {
            path: f.path().to_str().unwrap().into(),
            reload_interval: Duration::ZERO,
        })
        .unwrap();

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer original-token"
        );

        // Simulate Kubernetes secret rotation.
        f.reopen().unwrap();
        std::fs::write(f.path(), "rotated-token").unwrap();

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer rotated-token"
        );
    }

    #[test]
    fn bearer_token_file_not_found_returns_error_with_path() {
        let path = "/nonexistent/path/to/token";
        let state = AuthState::from_config(AuthTokenConfig::File {
            path: path.into(),
            reload_interval: Duration::ZERO,
        })
        .unwrap();

        let err = state.bearer_token().unwrap_err();
        assert!(err.contains(path), "error should contain path: {err}");
    }

    // -- serde round-trips --

    #[test]
    fn auth_token_config_inline_deserializes() {
        let toml = r#"type = "inline"
value = "my-token""#;
        let cfg: AuthTokenConfig = toml::from_str(toml).unwrap();
        assert!(matches!(cfg, AuthTokenConfig::Inline { value } if value.inner() == "my-token"));
    }

    #[test]
    fn auth_token_config_inline_rejects_unknown_field() {
        let toml = r#"type = "inline"
value = "tok"
extra = "nope""#;
        assert!(toml::from_str::<AuthTokenConfig>(toml).is_err());
    }

    #[test]
    fn auth_token_config_file_deserializes() {
        let toml = r#"type = "file"
path = "/var/run/secrets/token""#;
        let cfg: AuthTokenConfig = toml::from_str(toml).unwrap();
        assert!(
            matches!(cfg, AuthTokenConfig::File { path, .. } if path == "/var/run/secrets/token")
        );
    }

    #[test]
    fn auth_token_config_missing_type_fails() {
        let toml = r#"value = "token""#;
        assert!(toml::from_str::<AuthTokenConfig>(toml).is_err());
    }

    #[test]
    fn auth_token_config_unknown_type_fails() {
        let toml = r#"type = "env""#;
        assert!(toml::from_str::<AuthTokenConfig>(toml).is_err());
    }

    fn file_state(path: &std::path::Path, reload_interval: Duration) -> AuthState {
        AuthState::from_config(AuthTokenConfig::File {
            path: path.to_str().unwrap().into(),
            reload_interval,
        })
        .unwrap()
    }

    #[test]
    fn test_file_token_served_from_cache_within_reload_interval() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "first-token").unwrap();
        let state = file_state(f.path(), Duration::from_secs(60));
        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer first-token"
        );

        std::fs::write(f.path(), "second-token").unwrap();

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer first-token"
        );
    }

    #[test]
    fn test_file_token_reread_once_reload_interval_has_passed() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "first-token").unwrap();
        let state = file_state(f.path(), Duration::from_millis(50));
        state.bearer_token().unwrap();

        std::fs::write(f.path(), "second-token").unwrap();
        std::thread::sleep(Duration::from_millis(100));

        assert_eq!(
            state.bearer_token().unwrap().to_str().unwrap(),
            "Bearer second-token"
        );
    }

    #[test]
    fn test_file_token_read_failure_cached_within_reload_interval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let state = file_state(&path, Duration::from_secs(60));
        let first = state.bearer_token();
        assert!(
            matches!(&first, Err(err) if err.contains("failed to read token file")),
            "{first:?}"
        );

        std::fs::write(&path, "late-token").unwrap();

        let second = state.bearer_token();
        assert!(
            matches!(&second, Err(err) if err.contains("failed to read token file")),
            "{second:?}"
        );
    }

    #[test]
    fn test_file_token_reload_interval_defaults_to_two_seconds() {
        let cfg: AuthTokenConfig = toml::from_str(
            r#"type = "file"
path = "/var/run/secrets/token""#,
        )
        .unwrap();
        assert!(matches!(
            cfg,
            AuthTokenConfig::File { reload_interval, .. } if reload_interval == Duration::from_secs(2)
        ));
    }

    #[test]
    fn test_file_token_reload_interval_secs_alias_accepts_fractional_seconds() {
        let cfg: AuthTokenConfig = toml::from_str(
            r#"type = "file"
path = "/var/run/secrets/token"
reload_interval_secs = 0.5"#,
        )
        .unwrap();
        assert!(matches!(
            cfg,
            AuthTokenConfig::File { reload_interval, .. } if reload_interval == Duration::from_millis(500)
        ));
    }

    fn file_token(state: &AuthState) -> &FileToken {
        match &state.token {
            AuthToken::File(file) => file,
            AuthToken::Static(_) => panic!("expected a file token"),
        }
    }

    #[test]
    fn test_file_token_stale_token_served_while_another_caller_reloads() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "first-token").unwrap();
        let state = file_state(f.path(), Duration::from_millis(50));
        state.bearer_token().unwrap();
        std::fs::write(f.path(), "second-token").unwrap();
        std::thread::sleep(Duration::from_millis(100));

        let reloading = file_token(&state).reloading.lock().unwrap();
        let during = state.bearer_token();
        drop(reloading);
        let after = state.bearer_token();

        assert_eq!(during.unwrap().to_str().unwrap(), "Bearer first-token");
        assert_eq!(after.unwrap().to_str().unwrap(), "Bearer second-token");
    }

    #[test]
    fn test_file_token_first_read_waits_for_reload_in_progress() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "only-token").unwrap();
        let state = file_state(f.path(), Duration::from_secs(60));
        let reloading = file_token(&state).reloading.lock().unwrap();

        let read = std::thread::scope(|scope| {
            let reader = scope.spawn(|| state.bearer_token());
            std::thread::sleep(Duration::from_millis(50));
            drop(reloading);
            reader.join().unwrap()
        });

        assert_eq!(read.unwrap().to_str().unwrap(), "Bearer only-token");
    }
}
