# server

## Setup

* Install rust
* `cargo install migrant --features postgres`
* The following steps assume you are in the `server/` directory  
* Create a `.env` by copying the `.env.sample`.
* Setup a postgres db with the `DB_*` values listed in your env.
* `./source_env.sh`, or use a tool like autoenv. `migrant` needs to see your DB env values.  
* `migrant setup`
* `migrant apply -a`
* Create a spotify "app" here https://developer.spotify.com/dashboard/applications
* Copy your `SPOTIFY_CLIENT_ID` and `SPOTIFY_CLIENT_SECRET` to your `.env`
* `./source_env.sh`, or use a tool like autoenv.
* `cargo run`, note that `sqlx` needs to see a `DATABASE_URL` env at compile time
  to validate database queries.
