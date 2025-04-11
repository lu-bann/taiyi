FROM lukemathwalker/cargo-chef:latest-rust-1.85.0 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json
RUN apt update &&apt install -y protobuf-compiler
# Install SP1 toolchain
RUN curl -L https://sp1.succinct.xyz | bash
RUN ~/.sp1/bin/sp1up --version v4.1.7 && ~/.sp1/bin/cargo-prove prove --version
ENV PATH="~/.sp1/bin:${PATH}"

# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release

# We do not need the Rust toolchain to run the binary!
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y libssl-dev
WORKDIR /app
COPY --from=builder /app/target/release/taiyi* /usr/local/bin

LABEL org.opencontainers.image.source = "https://github.com/lu-bann/taiyi"

ENTRYPOINT ["/usr/local/bin/taiyi"]