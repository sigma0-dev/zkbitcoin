# Build the `zkbtc` binary
FROM rust:1.76 as build

WORKDIR /app

COPY ./src ./src
COPY Cargo.* .

RUN cargo build --release

# Install dependencies and copy the `zkbtc` binary
FROM ubuntu:latest

RUN apt update;  \
    apt install -y curl libatomic1;  \
    curl https://pkgx.sh | sh;  \
    pkgx install node npm;  \
    npm install -g snarkjs@latest

ENV PATH=/root/.local/bin:$PATH
COPY --link --from=build /app/target/release/zkbtc-admin /usr/local/bin/

WORKDIR /app

ENV RUST_LOG=debug
