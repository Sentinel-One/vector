The `component_sent_bytes_total` metric of sinks built on `HttpBatchService` (for example `http`, `splunk_hec_logs`, `splunk_hec_metrics`, `elasticsearch`) now exists from startup and is no longer removed by `expire_metrics_secs` while the sink is idle. The metric no longer carries the `endpoint` and `protocol` tags.

authors: nafiul.khan
