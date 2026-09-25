Added a `--worker-stack-size` flag / `WORKER_STACK_SIZE` env var to configure the stack size of the tokio runtime's worker threads. This lets deployments avoid stack overflows caused by deeply recursive `lua` or `vrl` transform logic without a code change.

authors: jagmeet-bali
