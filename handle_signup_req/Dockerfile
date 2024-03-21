FROM rust:alpine as builder

WORKDIR /ant_sumilation_backend/handle_signup_req

RUN apk add --no-cache musl-dev

ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL

COPY ./handle_signup_req/Cargo.toml .
COPY ./handle_signup_req/src ./src
COPY ./ant_rust_backend_lib/src ../ant_rust_backend_lib/src
COPY ./ant_rust_backend_lib/Cargo.toml ../ant_rust_backend_lib/

RUN cargo build --release

FROM alpine:latest

WORKDIR /usr/local/bin

COPY --from=builder /ant_sumilation_backend/handle_signup_req/target/release/handle_signup_req .

CMD [ "./handle_signup_req" ]