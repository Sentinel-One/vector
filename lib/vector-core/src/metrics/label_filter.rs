use metrics::{KeyName, Label};
use metrics_tracing_context::LabelFilter;

use crate::config::{OBSERVO_COMPONENT_NAME, OBSERVO_COMPONENT_VERSION, OBSERVO_LAST_UPDATE_TM};

#[derive(Debug, Clone)]
pub(crate) struct VectorLabelFilter;

impl LabelFilter for VectorLabelFilter {
    fn should_include_label(&self, metric_key: &KeyName, label: &Label) -> bool {
        let label_key = label.key();
        // HTTP Server-specific labels
        if metric_key.as_str().starts_with("http_server_")
            && (label_key == "method" || label_key == "path")
        {
            return true;
        }
        // gRPC Server-specific labels
        if metric_key.as_str().starts_with("grpc_server_")
            && (label_key == "grpc_method" || label_key == "grpc_service")
        {
            return true;
        }
        // Global labels
        label_key == "component_id"
            || label_key == "component_type"
            || label_key == "component_kind"
            || label_key == "buffer_type"
            // Observo labels: only include when a value is actually set
            || ((label_key == OBSERVO_COMPONENT_NAME
                || label_key == OBSERVO_COMPONENT_VERSION
                || label_key == OBSERVO_LAST_UPDATE_TM)
                && !label.value().is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter() -> VectorLabelFilter {
        VectorLabelFilter
    }

    fn key(name: &'static str) -> KeyName {
        KeyName::from(name)
    }

    fn label(k: &'static str, v: &'static str) -> Label {
        Label::new(k, v)
    }

    #[test]
    fn includes_standard_global_labels() {
        let k = key("some_metric");
        assert!(filter().should_include_label(&k, &label("component_id", "my_source")));
        assert!(filter().should_include_label(&k, &label("component_type", "aws_s3")));
        assert!(filter().should_include_label(&k, &label("component_kind", "source")));
        assert!(filter().should_include_label(&k, &label("buffer_type", "memory")));
    }

    #[test]
    fn excludes_unknown_label() {
        let k = key("some_metric");
        assert!(!filter().should_include_label(&k, &label("random_field", "value")));
    }

    #[test]
    fn includes_observo_name_when_non_empty() {
        let k = key("some_metric");
        assert!(filter().should_include_label(&k, &label(OBSERVO_COMPONENT_NAME, "snyk")));
    }

    #[test]
    fn includes_observo_version_when_non_empty() {
        let k = key("some_metric");
        assert!(filter().should_include_label(&k, &label(OBSERVO_COMPONENT_VERSION, "2")));
    }

    #[test]
    fn excludes_observo_name_when_empty() {
        let k = key("some_metric");
        assert!(!filter().should_include_label(&k, &label(OBSERVO_COMPONENT_NAME, "")));
    }

    #[test]
    fn excludes_observo_version_when_empty() {
        let k = key("some_metric");
        assert!(!filter().should_include_label(&k, &label(OBSERVO_COMPONENT_VERSION, "")));
    }

    #[test]
    fn includes_observo_last_update_tm_when_non_empty() {
        let k = key("some_metric");
        assert!(filter().should_include_label(&k, &label(OBSERVO_LAST_UPDATE_TM, "2026-06-10T12:00:00Z")));
    }

    #[test]
    fn excludes_observo_last_update_tm_when_empty() {
        let k = key("some_metric");
        assert!(!filter().should_include_label(&k, &label(OBSERVO_LAST_UPDATE_TM, "")));
    }

    #[test]
    fn includes_http_server_method_and_path() {
        let k = key("http_server_requests_total");
        assert!(filter().should_include_label(&k, &label("method", "GET")));
        assert!(filter().should_include_label(&k, &label("path", "/healthz")));
    }

    #[test]
    fn excludes_http_server_other_labels() {
        let k = key("http_server_requests_total");
        assert!(!filter().should_include_label(&k, &label("random_field", "value")));
    }

    #[test]
    fn includes_grpc_server_method_and_service() {
        let k = key("grpc_server_handled_total");
        assert!(filter().should_include_label(&k, &label("grpc_method", "SomeRpc")));
        assert!(filter().should_include_label(&k, &label("grpc_service", "MyService")));
    }
}
