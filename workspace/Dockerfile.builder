FROM rust:1.89-bullseye

RUN apt-get update && apt-get install -y \
    gcc-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    pkg-config \
    libssl-dev \
    clang \
    cmake \
    curl \
    git \
    build-essential

# Add aarch64 target to Rust toolchain
RUN rustup target add aarch64-unknown-linux-gnu

# Set the linker for cross-compilation
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc