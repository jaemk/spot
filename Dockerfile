FROM rust:1.50

RUN cargo install migrant --features postgres

# create a new empty shell
RUN mkdir -p /app
WORKDIR /app

RUN USER=root cargo new --bin server

# copy over your manifests
COPY ./server/Cargo.toml ./server/Cargo.toml
COPY ./server/Cargo.lock ./server/Cargo.lock

# this build step will cache your dependencies
WORKDIR /app/server
RUN cargo build --release
RUN rm src/*.rs

# copy all source/static/resource files
COPY ./server/src ./src
COPY ./server/sqlx-data.json ./sqlx-data.json
# COPY ./static ./static
# COPY ./templates ./templates

# build for release
RUN rm ./target/release/deps/server*

ENV SQLX_OFFLINE=true
RUN cargo build --release

# copy over git dir and embed latest commit hash
# WORKDIR /app
# COPY ./.git ./.git
# # make sure there's no trailing newline
# RUN git rev-parse HEAD | awk '{ printf "%s", $0 >"commit_hash.txt" }'
# RUN rm -rf ./.git
# RUN cp commit_hash.txt server/commit_hash.txt

WORKDIR /app

COPY ./bin ./bin
COPY ./server/Migrant.toml ./server/Migrant.toml
COPY ./server/migrations ./server/migrations

# copy out the binary and delete the build artifacts
RUN cp ./server/target/release/server ./bin/server
RUN rm -rf ./server/target

CMD ["./bin/start.sh"]
