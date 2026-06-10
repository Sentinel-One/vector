use vector_config::configurable_component;

/// Label key for the Observo component name.
pub const OBSERVO_COMPONENT_NAME: &str = "observo_component_name";

/// Label key for the Observo component version.
pub const OBSERVO_COMPONENT_VERSION: &str = "observo_component_version";

/// Observo-specific metadata attached to a component.
///
/// Values are emitted in tracing spans and propagated as Prometheus labels.
#[configurable_component]
#[derive(Clone, Debug, Default)]
pub struct ObservoMetadata {
    /// Human-readable name for this component (e.g. "snyk", "crowdstrike").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observo_component_name: Option<String>,

    /// Version of the template or collector used to generate this component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observo_component_version: Option<String>,
}

impl ObservoMetadata {
    /// Returns `(name, version)` as borrowed str slices, falling back to `""`.
    pub fn span_values(&self) -> (&str, &str) {
        (
            self.observo_component_name.as_deref().unwrap_or(""),
            self.observo_component_version.as_deref().unwrap_or(""),
        )
    }

    /// Returns `(name, version)` as owned Strings, falling back to `""`.
    /// Use this when the values need to outlive the `ObservoMetadata` borrow
    /// (e.g. before an `async move` closure captures them).
    pub fn span_values_owned(&self) -> (String, String) {
        (
            self.observo_component_name.clone().unwrap_or_default(),
            self.observo_component_version.clone().unwrap_or_default(),
        )
    }
}
