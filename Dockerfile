# Stage 1: Planner - Analyze dependencies
FROM rust:1.88-bookworm as planner
WORKDIR /app
RUN cargo install cargo-chef
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 2: Cacher - Build dependencies only
FROM rust:1.88-bookworm as cacher
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Stage 3: Builder - Build the application
FROM rust:1.88-bookworm as builder
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy cached dependencies from cacher stage
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo

# Copy source code
COPY . .

# Build arguments for metadata
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

# Build the broadcaster binary
RUN cargo build --release --bin railgun-broadcaster

# Stage 4: Runtime - Minimal production image
FROM debian:bookworm-slim
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -u 1000 -m -s /bin/bash broadcaster && \
    mkdir -p /app/config && \
    chown -R broadcaster:broadcaster /app

# Copy binary from builder
COPY --from=builder /app/target/release/railgun-broadcaster /app/broadcaster

# Copy example config (for reference only, not used)
COPY --from=builder /app/config.example.yaml /app/config.example.yaml

# Add metadata labels
LABEL org.opencontainers.image.title="RAILGUN Broadcaster"
LABEL org.opencontainers.image.description="RAILGUN privacy system broadcaster for relaying private transactions to Ethereum"
LABEL org.opencontainers.image.vendor="RAILGUN"
LABEL org.opencontainers.image.source="https://github.com/triamazikamno/railgun-broadcaster"
LABEL org.opencontainers.image.version="${GIT_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"

# Switch to non-root user
USER broadcaster

# Health check - verify process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -x broadcaster || exit 1

ENTRYPOINT ["/app/broadcaster"]
CMD ["--cfg", "/app/config/config.yaml"]
