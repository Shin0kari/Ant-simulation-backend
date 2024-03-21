FROM rust:alpine as builder

WORKDIR /app

RUN apk add --no-cache musl-dev

ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL

COPY ./rust_runner/Cargo.toml .
COPY ./rust_runner/src ./src 

RUN cargo build --release

FROM alpine:latest

WORKDIR /usr/local/bin

COPY --from=builder /app/target/release/rust_runner .
COPY ./rust_runner/access_check.json .

CMD [ "./rust_runner" ]