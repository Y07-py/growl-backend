# Step 1: Extraction of dependencies
FROM lukemathwalker/cargo-chef:latest-rust-1.95-bookworm AS planner
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Step 2: Building dependencies
FROM lukemathwalker/cargo-chef:latest-rust-1.95-bookworm AS cacher
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
# Building cache from dependencies
RUN cargo chef cook --release --recipe-path recipe.json

# Step 3: Building app
FROM rust:1.95-bookworm AS builder
WORKDIR /app
COPY . .
# Copy cached dependencies.
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
# Building app
RUN cargo build --release

# Step 4: Runtime
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# Install minimum library needed for execution.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Makr non root user.
RUN useradd -ms /bin/bash appuser
USER appuser

# COPY build binary.
COPY --from=builder /app/target/release/growl-backend .

# Setting port number
EXPOSE 8080

CMD ["./growl-backend"]
