# Start with image that has the Rust toolchain installed
FROM rust:1.85-alpine AS chef
USER root

# Add necessary dependencies for OpenSSL and pkg-config
RUN apk add --no-cache musl-dev pkgconf openssl-dev

# Add cargo-chef to cache dependencies
RUN cargo install cargo-chef

WORKDIR /app

FROM chef AS planner
COPY . .

# Capture info needed to build dependencies
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --release --bin auth-service

# We do not need the Rust toolchain to run the binary!
# Start with a minimal image and copy over the binary and assets folder.
FROM debian:bullseye-slim AS runtime

# Install necessary runtime dependencies
RUN apt-get update && apt-get install -y libssl1.1 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/auth-service /usr/local/bin
COPY --from=builder /app/assets /app/assets

ENTRYPOINT ["/usr/local/bin/auth-service"]
