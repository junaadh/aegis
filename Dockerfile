FROM rust:1-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY bin ./bin
COPY crates ./crates
COPY migrations ./migrations

RUN cargo build --release -p aegisd --bin aegisd

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --system aegis \
  && useradd --system --gid aegis --home-dir /var/lib/aegis --create-home aegis

WORKDIR /var/lib/aegis

COPY --from=builder /app/target/release/aegisd /usr/local/bin/aegisd

RUN mkdir -p /etc/aegis && chown -R aegis:aegis /etc/aegis /var/lib/aegis

USER aegis

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/aegisd"]
CMD ["/etc/aegis/aegis.toml"]
