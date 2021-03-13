# spot

> track your spotify play history


## Setup

* Install rust
* `cargo install migrant --features postgres`
* Create a `.env.local` and copy the values listed in `.env`.
  Anything listed here will override what's in the `.env` file.
* Setup a postgres db with the `DB_*` values listed in your env.
* `migrant setup`
* `migrant apply -a`
* Create a spotify "app" here https://developer.spotify.com/dashboard/applications
* Copy your `SPOTIFY_CLIENT_ID` and `SPOTIFY_CLIENT_SECRET` to your `.env.local`
* `cargo run`
