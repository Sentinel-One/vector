The `logstash` source now caps how far a compressed frame may inflate via the new
`max_decompressed_bytes` option (default 256 MiB), and rejects nested compressed frames outright.
Both previously allowed a decompression bomb to exhaust the heap.
