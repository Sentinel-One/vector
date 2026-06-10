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

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> ObservoMetadata {
        ObservoMetadata {
            observo_component_name: Some("snyk".to_string()),
            observo_component_version: Some("2".to_string()),
        }
    }

    fn empty() -> ObservoMetadata {
        ObservoMetadata::default()
    }

    #[test]
    fn span_values_when_set() {
        let meta = full();
        let (name, version) = meta.span_values();
        assert_eq!(name, "snyk");
        assert_eq!(version, "2");
    }

    #[test]
    fn span_values_when_none_returns_empty_str() {
        let meta = empty();
        let (name, version) = meta.span_values();
        assert_eq!(name, "");
        assert_eq!(version, "");
    }

    #[test]
    fn span_values_owned_when_set() {
        let (name, version) = full().span_values_owned();
        assert_eq!(name, "snyk");
        assert_eq!(version, "2");
    }

    #[test]
    fn span_values_owned_when_none_returns_empty_string() {
        let (name, version) = empty().span_values_owned();
        assert_eq!(name, "");
        assert_eq!(version, "");
    }

    #[test]
    fn serde_round_trip_with_values() {
        let original = full();
        let yaml = serde_yaml::to_string(&original).unwrap();
        let roundtripped: ObservoMetadata = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(roundtripped.observo_component_name, original.observo_component_name);
        assert_eq!(roundtripped.observo_component_version, original.observo_component_version);
    }

    #[test]
    fn serde_deserialize_partial_fields() {
        let yaml = "observo_component_name: crowdstrike\n";
        let meta: ObservoMetadata = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(meta.observo_component_name.as_deref(), Some("crowdstrike"));
        assert!(meta.observo_component_version.is_none());
    }

    #[test]
    fn serde_serialize_skips_none_fields() {
        let yaml = serde_yaml::to_string(&empty()).unwrap();
        assert!(!yaml.contains("observo_component_name"));
        assert!(!yaml.contains("observo_component_version"));
    }
}
