# syntax=docker/dockerfile:1.4
FROM rust as build

WORKDIR /app

COPY ./src ./src
COPY Cargo.* .

RUN cargo build --release

FROM ubuntu:latest

RUN apt update; apt install -y nodejs npm; npm install -g snarkjs@latest

COPY --from=build /app/target/release/zkbtc /usr/local/bin/

ENV RUST_LOG=debug

ENTRYPOINT ["/app/target/release/zkbtc"]
CMD ["start-committee-node", "--key-path=examples/committee/key-0.json", "--publickey-package-path=examples/committee/publickey-package.json", "--address=127.0.0.1:8891"]
