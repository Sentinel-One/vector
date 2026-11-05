The `prometheus_remote_write` sink has a new `bucket` option. It splits metrics into buckets by a hash of chosen tags, and sends each bucket's requests one at a time, retries included, while different buckets go out in parallel up to `request.concurrency`. A receiver therefore never sees a series out of order, even with concurrent requests. `bucket.header`, when set, names each request's bucket in a header, for receivers that route on it.

authors: yoonlee-s1
