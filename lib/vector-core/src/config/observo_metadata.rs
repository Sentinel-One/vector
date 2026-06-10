use vector_config::configurable_component;

/// Label key for the Observo component name (maps to `tmpl_name`).
pub const OBSERVO_COMPONENT_NAME: &str = "observo_component_name";

/// Label key for the Observo component template version (maps to `tmpl_ver`).
pub const OBSERVO_COMPONENT_VERSION: &str = "observo_component_version";

/// Label key for the MSSP integration name (maps to `int_name`).
pub const OBSERVO_INTEGRATION_NAME: &str = "observo_integration_name";

/// Label key for the source/sink version in use (maps to `ver`).
pub const OBSERVO_SOURCE_VERSION: &str = "observo_source_version";

/// Label key for the timestamp of the last user update to this component's config.
pub const OBSERVO_LAST_UPDATE_TM: &str = "observo_last_update_tm";

/// All Observo label keys in one place — iterate this to register/check them as a group.
pub const OBSERVO_LABEL_KEYS: &[&str] = &[
    OBSERVO_COMPONENT_NAME,
    OBSERVO_COMPONENT_VERSION,
    OBSERVO_INTEGRATION_NAME,
    OBSERVO_SOURCE_VERSION,
    OBSERVO_LAST_UPDATE_TM,
];

/// Flat view of all Observo span/label values with borrowed lifetimes.
/// Returned by [`ObservoMetadata::span_values`]; all fields fall back to `""`.
pub struct SpanValues<'a> {
    pub component_name: &'a str,
    pub component_version: &'a str,
    pub integration_name: &'a str,
    pub source_version: &'a str,
    pub last_update_tm: &'a str,
}

impl Default for SpanValues<'static> {
    fn default() -> Self {
        Self {
            component_name: "",
            component_version: "",
            integration_name: "",
            source_version: "",
            last_update_tm: "",
        }
    }
}

/// Owned equivalent of [`SpanValues`], for use before `async move` closures.
#[derive(Clone, Default)]
pub struct SpanValuesOwned {
    pub component_name: String,
    pub component_version: String,
    pub integration_name: String,
    pub source_version: String,
    pub last_update_tm: String,
}

/// Observo-specific metadata attached to a component.
///
/// Values are emitted in tracing spans and propagated as Prometheus labels.
#[configurable_component]
#[derive(Clone, Debug, Default)]
pub struct ObservoMetadata {
    /// Human-readable name for this component (e.g. "snyk", "crowdstrike"). Maps to `tmpl_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observo_component_name: Option<String>,

    /// Version of the template used to generate this component. Maps to `tmpl_ver`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observo_component_version: Option<String>,

    /// MSSP integration name. Maps to `int_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observo_integration_name: Option<String>,

    /// Version of the source or sink component in use. Maps to `ver`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observo_source_version: Option<String>,

    /// ISO 8601 timestamp of when a user last updated this component's configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observo_last_update_tm: Option<String>,
}

impl ObservoMetadata {
    /// Returns all span/label values as borrowed str slices, falling back to `""`.
    pub fn span_values(&self) -> SpanValues<'_> {
        SpanValues {
            component_name: self.observo_component_name.as_deref().unwrap_or(""),
            component_version: self.observo_component_version.as_deref().unwrap_or(""),
            integration_name: self.observo_integration_name.as_deref().unwrap_or(""),
            source_version: self.observo_source_version.as_deref().unwrap_or(""),
            last_update_tm: self.observo_last_update_tm.as_deref().unwrap_or(""),
        }
    }

    /// Returns all span/label values as owned Strings, falling back to `""`.
    /// Use this when the values need to outlive the `ObservoMetadata` borrow
    /// (e.g. before an `async move` closure captures them).
    pub fn span_values_owned(&self) -> SpanValuesOwned {
        SpanValuesOwned {
            component_name: self.observo_component_name.clone().unwrap_or_default(),
            component_version: self.observo_component_version.clone().unwrap_or_default(),
            integration_name: self.observo_integration_name.clone().unwrap_or_default(),
            source_version: self.observo_source_version.clone().unwrap_or_default(),
            last_update_tm: self.observo_last_update_tm.clone().unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> ObservoMetadata {
        ObservoMetadata {
            observo_component_name: Some("snyk".to_string()),
            observo_component_version: Some("2".to_string()),
            observo_integration_name: Some("snyk-mssp".to_string()),
            observo_source_version: Some("1.0.0".to_string()),
            observo_last_update_tm: Some("2026-06-10T12:00:00Z".to_string()),
        }
    }

    fn empty() -> ObservoMetadata {
        ObservoMetadata::default()
    }

    #[test]
    fn span_values_when_set() {
        let meta = full();
        let v = meta.span_values();
        assert_eq!(v.component_name, "snyk");
        assert_eq!(v.component_version, "2");
        assert_eq!(v.integration_name, "snyk-mssp");
        assert_eq!(v.source_version, "1.0.0");
        assert_eq!(v.last_update_tm, "2026-06-10T12:00:00Z");
    }

    #[test]
    fn span_values_when_none_returns_empty_str() {
        let meta = empty();
        let v = meta.span_values();
        assert_eq!(v.component_name, "");
        assert_eq!(v.component_version, "");
        assert_eq!(v.integration_name, "");
        assert_eq!(v.source_version, "");
        assert_eq!(v.last_update_tm, "");
    }

    #[test]
    fn span_values_owned_when_set() {
        let v = full().span_values_owned();
        assert_eq!(v.component_name, "snyk");
        assert_eq!(v.component_version, "2");
        assert_eq!(v.integration_name, "snyk-mssp");
        assert_eq!(v.source_version, "1.0.0");
        assert_eq!(v.last_update_tm, "2026-06-10T12:00:00Z");
    }

    #[test]
    fn span_values_owned_when_none_returns_empty_string() {
        let v = empty().span_values_owned();
        assert_eq!(v.component_name, "");
        assert_eq!(v.component_version, "");
        assert_eq!(v.integration_name, "");
        assert_eq!(v.source_version, "");
        assert_eq!(v.last_update_tm, "");
    }

    #[test]
    fn serde_round_trip_with_values() {
        let original = full();
        let yaml = serde_yaml::to_string(&original).unwrap();
        let rt: ObservoMetadata = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(rt.observo_component_name, original.observo_component_name);
        assert_eq!(rt.observo_component_version, original.observo_component_version);
        assert_eq!(rt.observo_integration_name, original.observo_integration_name);
        assert_eq!(rt.observo_source_version, original.observo_source_version);
        assert_eq!(rt.observo_last_update_tm, original.observo_last_update_tm);
    }

    #[test]
    fn serde_deserialize_partial_fields() {
        let yaml = "observo_component_name: crowdstrike\n";
        let meta: ObservoMetadata = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(meta.observo_component_name.as_deref(), Some("crowdstrike"));
        assert!(meta.observo_component_version.is_none());
        assert!(meta.observo_integration_name.is_none());
        assert!(meta.observo_source_version.is_none());
        assert!(meta.observo_last_update_tm.is_none());
    }

    #[test]
    fn serde_serialize_skips_none_fields() {
        let yaml = serde_yaml::to_string(&empty()).unwrap();
        assert!(!yaml.contains("observo_component_name"));
        assert!(!yaml.contains("observo_component_version"));
        assert!(!yaml.contains("observo_integration_name"));
        assert!(!yaml.contains("observo_source_version"));
        assert!(!yaml.contains("observo_last_update_tm"));
    }
}
