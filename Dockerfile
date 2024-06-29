FROM rust:1.79.0-buster

RUN apt update && apt install -y build-essential openssl libssl-dev pkg-config

WORKDIR /usr/src/taiyi
COPY . .

RUN cargo build --release

ENTRYPOINT ["./target/release/luban"]