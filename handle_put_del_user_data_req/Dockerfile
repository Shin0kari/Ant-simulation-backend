FROM rust:alpine as builder

WORKDIR /app

RUN apk add --no-cache musl-dev

ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL

COPY /handle_put_del_user_data_req/Cargo.toml .
COPY /handle_put_del_user_data_req/src ./src 

RUN cargo build --release

FROM alpine:latest

WORKDIR /usr/local/bin

COPY --from=builder /app/target/release/handle_put_del_user_data_req .

CMD [ "./handle_put_del_user_data_req" ]