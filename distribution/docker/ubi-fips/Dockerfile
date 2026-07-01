FROM artifactory.eng.sentinelone.tech/docker-release/common/ubuntu-base/ubuntu:2.0.77 AS builder

WORKDIR /vector

COPY vector-*-unknown-linux-*.tar.gz ./
RUN tar -xvf vector-*-$(uname -m)-unknown-linux-*.tar.gz --strip-components=2

RUN mkdir -p /var/lib/vector

FROM artifactory.eng.sentinelone.tech/docker-release/common/ubuntu-base/ubuntu:2.0.77

# Install dependencies for Vector and FIPS
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl-dev \
      ca-certificates \
      tzdata \
      systemd \
      && apt-get clean \
      && rm -rf /var/lib/apt/lists/*

# Set environment for Rust to use system OpenSSL
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf.fips
RUN echo "export OPENSSL_MODULES=/usr/lib/$(uname -m)-linux-gnu/ossl-modules" > /etc/profile.d/openssl-fips.sh

# Copy from builder stage
COPY --from=builder /vector/bin/* /usr/bin/
COPY --from=builder /vector/config/README.md /etc/vector/README.md
COPY --from=builder /var/lib/vector /var/lib/vector

# Smoke test
RUN ["vector", "--version"]

USER root

ENTRYPOINT ["/bin/bash", "-c", ". /etc/profile.d/openssl-fips.sh && exec /usr/bin/vector"]
