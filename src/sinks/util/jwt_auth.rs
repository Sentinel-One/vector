use vector_lib::configurable::configurable_component;
use vector_lib::sensitive_string::SensitiveString;

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
/// File path (re-read on every request for Kubernetes secret rotation):
/// ```toml
/// token.type = "file"
/// token.path = "/var/run/secrets/vector/token"
/// ```
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
    /// The file is re-read on **every request** so that a rotated Kubernetes secret
    /// volume mount is picked up automatically without restarting the agent.
    File {
        /// Path to the token file.
        path: String,
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
    /// Path to a file re-read on every request (K8s secret rotation).
    File(String),
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
            AuthTokenConfig::File { path } => AuthToken::File(path),
        };

        Ok(Self { token })
    }

    /// Returns the current bearer token as a gRPC `MetadataValue`.
    ///
    /// For [`AuthToken::Static`] this is a cheap clone of the pre-built value.
    /// For [`AuthToken::File`] the token file is re-read on every call so that
    /// a rotated Kubernetes secret is picked up without restarting the agent.
    ///
    /// Returns an error message string on failure; the caller is responsible for
    /// converting it to the appropriate error type.
    pub fn bearer_token(
        &self,
    ) -> Result<tonic::metadata::MetadataValue<tonic::metadata::Ascii>, String> {
        match &self.token {
            AuthToken::Static(value) => Ok(value.clone()),
            AuthToken::File(path) => {
                let raw = std::fs::read_to_string(path)
                    .map_err(|err| format!("failed to read token file '{}': {err}", path))?;
                let token = raw.trim();
                format!("Bearer {token}")
                    .parse::<tonic::metadata::MetadataValue<_>>()
                    .map_err(|err| format!("token file contains invalid characters: {err}"))
            }
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
        let state = AuthState::from_config(AuthTokenConfig::File { path: path.into() }).unwrap();

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
            matches!(cfg, AuthTokenConfig::File { path } if path == "/var/run/secrets/token")
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
}
