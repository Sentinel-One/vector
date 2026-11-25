use aws_sdk_sns::Client as SnsClient;

use crate::aws::RegionOrEndpoint;
use vector_lib::internal_event::{BytesSent, Registered};

use crate::config::{
    AcknowledgementsConfig, DataType, GenerateConfig, Input, ProxyConfig, SinkConfig, SinkContext,
};
use vector_lib::configurable::configurable_component;

use super::{
    client::SnsMessagePublisher, message_deduplication_id, message_group_id, BaseSSSinkConfig,
    SSRequestBuilder, SSSink,
};
use crate::aws::create_sink_client;
use crate::aws::ClientBuilder;

/// Configuration for the `aws_sns` sink.
#[configurable_component(sink(
    "aws_sns",
    "Publish observability events to AWS Simple Notification Service topics."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct SnsSinkConfig {
    /// The ARN of the Amazon SNS topic to which messages are sent.
    #[configurable(validation(format = "uri"))]
    #[configurable(metadata(docs::examples = "arn:aws:sns:us-east-2:123456789012:MyTopic"))]
    pub(super) topic_arn: String,

    #[serde(flatten)]
    pub(super) region: RegionOrEndpoint,

    #[serde(flatten)]
    pub(super) base_config: BaseSSSinkConfig,
}

impl GenerateConfig for SnsSinkConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(
            r#"topic_arn = "arn:aws:sns:us-east-2:123456789012:MyTopic"
            region = "us-east-2"
            encoding.codec = "json""#,
        )
        .unwrap()
    }
}

impl SnsSinkConfig {
    pub(super) async fn create_client(
        &self,
        proxy: &ProxyConfig,
        bytes_sent: Registered<BytesSent>,
    ) -> crate::Result<SnsClient> {
        create_sink_client::<SnsClientBuilder>(
            &SnsClientBuilder {},
            &self.base_config.auth,
            self.region.region(),
            self.region.endpoint(),
            proxy,
            self.base_config.tls.as_ref(),
            None,
            bytes_sent,
        )
        .await
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "aws_sns")]
impl SinkConfig for SnsSinkConfig {
    async fn build(
        &self,
        cx: SinkContext,
    ) -> crate::Result<(crate::sinks::VectorSink, crate::sinks::Healthcheck)> {
        let client = self.create_client(&cx.proxy, cx.bytes_sent()).await?;

        let publisher = SnsMessagePublisher::new(client.clone(), self.topic_arn.clone());

        let healthcheck = Box::pin(healthcheck(client.clone(), self.topic_arn.clone()));

        let message_group_id = message_group_id(
            self.base_config.message_group_id.clone(),
            self.topic_arn.ends_with(".fifo"),
        );
        let message_deduplication_id =
            message_deduplication_id(self.base_config.message_deduplication_id.clone());

        let sink = SSSink::new(
            SSRequestBuilder::new(
                message_group_id?,
                message_deduplication_id?,
                self.base_config.encoding.clone(),
            )?,
            self.base_config.request,
            publisher,
        )?;
        Ok((
            crate::sinks::VectorSink::from_event_streamsink(sink),
            healthcheck,
        ))
    }

    fn input(&self) -> Input {
        Input::new(self.base_config.encoding.config().input_type() & DataType::Log)
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.base_config.acknowledgements
    }
}

pub(super) struct SnsClientBuilder;

impl ClientBuilder for SnsClientBuilder {
    type Client = aws_sdk_sns::client::Client;

    fn build(&self, config: &aws_types::SdkConfig) -> Self::Client {
        aws_sdk_sns::client::Client::new(config)
    }
}

pub(super) async fn healthcheck(client: SnsClient, topic_arn: String) -> crate::Result<()> {
    client
        .get_topic_attributes()
        .topic_arn(topic_arn.clone())
        .send()
        .await
        .map(|_| ())
        .map_err(Into::into)
}

#[cfg(test)]
mod sent_bytes_tests {
    use super::*;

    #[tokio::test]
    async fn sent_bytes_series_exists_after_build() {
        let config: SnsSinkConfig = toml::from_str(
            r#"
            topic_arn = "arn:aws:sns:us-east-1:000000000000:t"
            encoding.codec = "json"
            region = "us-east-1"
            endpoint = "http://127.0.0.1:1"
            auth.access_key_id = "x"
            auth.secret_access_key = "x"
        "#,
        )
        .unwrap();
        crate::test_util::components::assert_sent_bytes_series_after_build(config).await;
    }
}
