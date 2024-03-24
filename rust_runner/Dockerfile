FROM rust:alpine as builder

WORKDIR /ant_sumilation_backend/rust_runner

RUN apk add --no-cache musl-dev

ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL

COPY ./rust_runner/Cargo.toml .
COPY ./rust_runner/src ./src
COPY ./ant_rust_backend_lib/src ../ant_rust_backend_lib/src
COPY ./ant_rust_backend_lib/Cargo.toml ../ant_rust_backend_lib/

RUN cargo build --release

FROM alpine:latest

WORKDIR /usr/local/bin

COPY --from=builder /ant_sumilation_backend/rust_runner/target/release/rust_runner .
COPY ./ant_rust_backend_lib/src/data/access_check.json .

CMD [ "./rust_runner" ]