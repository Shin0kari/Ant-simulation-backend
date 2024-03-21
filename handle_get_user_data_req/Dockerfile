FROM rust:alpine as builder

WORKDIR /ant_sumilation_backend/handle_get_user_data_req

RUN apk add --no-cache musl-dev

ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL

COPY ./handle_get_user_data_req/Cargo.toml .
COPY ./handle_get_user_data_req/src ./src/
COPY ./ant_rust_backend_lib/src ../ant_rust_backend_lib/src
COPY ./ant_rust_backend_lib/Cargo.toml ../ant_rust_backend_lib/

RUN cargo build --release

FROM alpine:latest

WORKDIR /usr/local/bin

COPY --from=builder /ant_sumilation_backend/handle_get_user_data_req/target/release/handle_get_user_data_req .

CMD [ "./handle_get_user_data_req" ]