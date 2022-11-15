# soundlog

> Track your spotify play history


## Setup

* Install rust
* `cargo install migrant --features postgres`
* Create a `.env` by copying the `.env.sample`. The migration tool (`migrant`),
  the server application, and the `sqlx`  database library will all automatically
  apply any values listed in your `.env` to the current environment, so you don't
  need to "source" the .env manually.
* Setup a postgres db with the `DB_*` values listed in your env.
* `migrant setup`
* `migrant apply -a`
* Create a spotify "app" here https://developer.spotify.com/dashboard/applications
* Copy your `SPOTIFY_CLIENT_ID` and `SPOTIFY_CLIENT_SECRET` to your `.env`
* `cargo run`, note that `sqlx` needs to see a `DATABASE_URL` (set in your `.env`)
  environment variable at compile time to validate database queries.

