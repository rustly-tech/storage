# Rustly artifact gateway.
FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY services ./services
RUN cargo build --release --locked -p rustly-artifact-gateway \
    && strip target/release/rustly-artifact-gateway

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=build /src/target/release/rustly-artifact-gateway /app/rustly-artifact-gateway
ENV RUSTLY_ARTIFACT_BIND=0.0.0.0:8081 \
    RUSTLY_LOG_FORMAT=json \
    RUST_LOG=info
EXPOSE 8081
USER nonroot:nonroot
ENTRYPOINT ["/app/rustly-artifact-gateway"]
