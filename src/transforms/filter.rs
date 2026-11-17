use vector_lib::config::{clone_input_definitions, LogNamespace};
use vector_lib::configurable::configurable_component;
use vector_lib::internal_event::{Count, InternalEventHandle as _, Registered};

use crate::{
    conditions::{AnyCondition, Condition},
    config::{
        DataType, GenerateConfig, Input, OutputId, TransformConfig, TransformContext,
        TransformOutput,
    },
    event::Event,
    internal_events::FilterEventsDropped,
    schema,
    transforms::{FunctionTransform, OutputBuffer, Transform},
};

/// Configuration for the `filter` transform.
#[configurable_component(transform("filter", "Filter events based on a set of conditions."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    #[configurable(derived)]
    /// The condition that every input event is matched against.
    ///
    /// If an event is matched by the condition, it is forwarded. Otherwise, the event is dropped.
    condition: AnyCondition,
}

impl From<AnyCondition> for FilterConfig {
    fn from(condition: AnyCondition) -> Self {
        Self { condition }
    }
}

impl GenerateConfig for FilterConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(r#"condition = ".message == \"value\"""#).unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "filter")]
impl TransformConfig for FilterConfig {
    async fn build(&self, context: &TransformContext) -> crate::Result<Transform> {
        Ok(Transform::function(Filter::new(
            self.condition.build(&context.enrichment_tables)?,
        )))
    }

    fn input(&self) -> Input {
        Input::all()
    }

    fn outputs(
        &self,
        _enrichment_tables: vector_lib::enrichment::TableRegistry,
        input_definitions: &[(OutputId, schema::Definition)],
        _: LogNamespace,
    ) -> Vec<TransformOutput> {
        vec![TransformOutput::new(
            DataType::all_bits(),
            clone_input_definitions(input_definitions),
        )]
    }

    fn enable_concurrency(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct Filter {
    condition: Condition,
    events_dropped: Registered<FilterEventsDropped>,
}

impl Filter {
    pub fn new(condition: Condition) -> Self {
        Self {
            condition,
            events_dropped: register!(FilterEventsDropped),
        }
    }
}

impl FunctionTransform for Filter {
    fn transform(&mut self, output: &mut OutputBuffer, event: Event) {
        let (result, event) = self.condition.check(event);
        if result {
            output.push(event);
        } else {
            self.events_dropped.emit(Count(1));
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use vector_lib::config::ComponentKey;
    use vector_lib::event::{Metric, MetricKind, MetricValue};

    use super::*;
    use crate::config::schema::Definition;
    use crate::{
        conditions::ConditionConfig,
        event::{Event, LogEvent},
        test_util::components::assert_transform_compliance,
        transforms::test::create_topology,
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<super::FilterConfig>();
    }

    #[tokio::test]
    async fn filter_basic() {
        assert_transform_compliance(async {
            let transform_config = FilterConfig::from(AnyCondition::from(ConditionConfig::IsLog));

            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) =
                create_topology(ReceiverStream::new(rx), transform_config).await;

            let mut log = Event::from(LogEvent::from("message"));
            tx.send(log.clone()).await.unwrap();

            log.set_source_id(Arc::new(ComponentKey::from("in")));
            log.set_upstream_id(Arc::new(OutputId::from("transform")));
            log.metadata_mut()
                .set_schema_definition(&Arc::new(Definition::default_legacy_namespace()));

            assert_eq!(out.recv().await.unwrap(), log);

            let metric = Event::from(Metric::new(
                "test metric",
                MetricKind::Incremental,
                MetricValue::Counter { value: 1.0 },
            ));
            tx.send(metric).await.unwrap();

            drop(tx);
            topology.stop().await;
            assert_eq!(out.recv().await, None);
        })
        .await;
    }

    #[tokio::test]
    async fn filter_with_predicate_condition_forwards_only_matching_events() {
        let transform_config = crate::config::format::deserialize::<FilterConfig>(
            indoc::indoc! {r#"
                condition:
                  type: predicate
                  when:
                    all:
                      - eq: { path: .operationName, value: NSGFlowEvents }
                      - not: { exists: .debug }
                      - cidr: { path: .src_ip, ranges: ["10.0.0.0/8"] }
                      - any:
                          - gt: { path: .bytes, value: 1000 }
                          - starts_with: { path: .rule, value: Deny }
            "#},
            crate::config::Format::Yaml,
        )
        .unwrap();

        let event = |json: serde_json::Value| {
            Event::from_json_value(json, vector_lib::config::LogNamespace::Legacy).unwrap()
        };
        let big_flow = event(serde_json::json!({
            "operationName": "NSGFlowEvents", "src_ip": "10.1.2.3", "bytes": "4096", "rule": "AllowWeb"
        }));
        let denied = event(serde_json::json!({
            "operationName": "NSGFlowEvents", "src_ip": "10.9.9.9", "bytes": 10, "rule": "DenyAll"
        }));
        let rejected = [
            serde_json::json!({"operationName": "NSGFlowEvents", "src_ip": "10.1.2.3", "bytes": 10, "rule": "AllowWeb"}),
            serde_json::json!({"operationName": "NSGFlowEvents", "src_ip": "8.8.8.8", "bytes": 4096, "rule": "AllowWeb"}),
            serde_json::json!({"operationName": "NSGFlowEvents", "src_ip": "10.1.2.3", "bytes": 4096, "debug": true}),
            serde_json::json!({"operationName": "Other", "src_ip": "10.1.2.3", "bytes": 4096}),
        ]
        .map(event);

        assert_transform_compliance(async {
            let (tx, rx) = mpsc::channel(8);
            let (topology, mut out) =
                create_topology(ReceiverStream::new(rx), transform_config).await;
            for e in rejected.into_iter().chain([big_flow, denied]) {
                tx.send(e).await.unwrap();
            }
            let mut passed = Vec::new();
            for _ in 0..2 {
                passed.push(out.recv().await.unwrap().as_log().get("rule").cloned());
            }
            assert_eq!(
                passed,
                vec![Some("AllowWeb".into()), Some("DenyAll".into())]
            );

            drop(tx);
            topology.stop().await;
            assert_eq!(out.recv().await, None);
        })
        .await;
    }

    #[test]
    fn filter_with_predicate_condition_rejects_unknown_operator() {
        let config = |op: &str| {
            crate::config::format::deserialize::<FilterConfig>(
                &format!("condition: {{ type: predicate, when: {{ {op}: {{ path: .a, value: 1 }} }} }}"),
                crate::config::Format::Yaml,
            )
        };
        assert!(config("eq").is_ok());
        assert!(config("equals").is_err());
    }
}
