The GELF chunked framer now defaults `pending_messages_limit` to 10000 and `max_length` to 8 MiB,
where both were previously unlimited. Both sit above the protocol's own ceiling of 128 chunks per
message, so a well-formed sender cannot reach them. Each is overridable.
