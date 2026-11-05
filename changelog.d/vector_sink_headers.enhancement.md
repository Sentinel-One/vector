The `vector` sink has a new `headers` option: gRPC metadata sent with every request, as a map of names to values. Values can use environment variables, for example `${VECTOR_SELF_POD_NAME}`, so a proxy in front of the receiving Vector can route each sender's requests consistently.

authors: yoonlee-s1
