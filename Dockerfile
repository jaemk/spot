FROM rust:1.58.1-bullseye as builder

RUN cargo install migrant --features postgres

# create a new empty shell
#RUN mkdir -p /app
#WORKDIR /app

RUN USER=root cargo new --bin spot
WORKDIR /spot

# copy over your manifests
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock

# this build step will cache your dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy all source/static/resource files
COPY ./src ./src
COPY ./sqlx-data.json ./sqlx-data.json
COPY ./static ./static
# COPY ./templates ./templates

# build for release
RUN rm ./target/release/deps/spot*

ENV SQLX_OFFLINE=true
RUN cargo build --release

# copy over git dir and embed latest commit hash
COPY ./.git ./.git
# make sure there's no trailing newline
RUN git rev-parse HEAD | awk '{ printf "%s", $0 >"commit_hash.txt" }'
RUN rm -rf ./.git

COPY ./bin ./bin
COPY ./Migrant.toml ./Migrant.toml
COPY ./migrations ./migrations

# copy out the binary and delete the build artifacts
RUN cp ./target/release/spot ./bin/spot
RUN rm -rf ./target

FROM debian:bullseye-slim
RUN apt-get update && apt-get install --yes ca-certificates curl
COPY --from=builder /spot ./spot
COPY --from=builder /usr/local/cargo/bin/migrant /usr/bin/migrant
WORKDIR /spot

CMD ["./bin/start.sh"]
