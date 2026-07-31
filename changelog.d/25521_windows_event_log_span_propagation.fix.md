The `windows_event_log` source now propagates the component tracing span into its spawned background tasks, so their internal logs and metrics are correctly tagged with the component.

authors: tot19
