FROM rust:1.49

# create a new empty shell
RUN mkdir -p /app
WORKDIR /app

RUN USER=root cargo new --bin server

# copy over your manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./server/Cargo.toml ./server/Cargo.toml

# this build step will cache your dependencies
WORKDIR /app/server
RUN cargo build --release
RUN rm src/*.rs

ENV SQLX_OFFLINE=true
# copy all source/static/resource files
COPY ./server/src ./src
# COPY ./static ./static
# COPY ./templates ./templates

# build for release
RUN rm ../target/release/deps/server*
RUN cargo build --release

# set the startup command to run your binary
CMD ["../target/release/server"]
