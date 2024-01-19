# Build the `zkbtc` binary
FROM rust as build

WORKDIR /app

COPY ./src ./src
COPY Cargo.* .

RUN cargo build --release

# Install dependencies and copy the `zkbtc` binary
FROM ubuntu:latest

RUN apt update; apt install -y nodejs npm; npm install -g snarkjs@latest

COPY --link --from=build /app/target/release/zkbtc /usr/local/bin/
COPY --link ./examples ./examples

WORKDIR /app
EXPOSE 8891

ENV RUST_LOG=debug
