create table tracks (
    id int8 primary key default id_gen(),
    user_id int8 not null references users(id),
    spotify_id text not null,
    played timestamptz not null,
    name text not null,
    raw jsonb not null,
    created timestamptz not null default now(),
    modified timestamptz not null default now()
);
create unique index track_played_at on tracks(spotify_id, played);
