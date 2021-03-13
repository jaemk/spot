create table spot.tracks (
    id int8 primary key default spot.id_gen(),
    user_id int8 not null references spot.users(id),
    spotify_id text not null,
    played timestamptz not null,
    name text not null,
    raw jsonb not null,
    created timestamptz not null default now(),
    modified timestamptz not null default now()
);
create unique index tracks_played_at_by_user on tracks(user_id, spotify_id, played);
create index tracks_user on tracks(user_id);