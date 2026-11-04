The `prometheus_remote_write` sink has a new `tenant_header` option that sets the name of the header carrying `tenant_id`. It defaults to `X-Scope-OrgID`, so existing configurations are unchanged. This lets the sink write to receivers that read the tenant from another header, such as Thanos Receive configured with `--receive.tenant-header`.

authors: yoonlee-s1
