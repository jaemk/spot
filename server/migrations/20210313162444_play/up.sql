begin;
create table spot.plays (
    id int8 primary key default spot.id_gen(),
    user_id int8 not null references spot.users(id),
    spotify_id text not null,
    played_at timestamptz not null,
    played_at_minute timestamptz not null,
    name text not null,
    raw jsonb not null,
    created timestamptz not null default now(),
    modified timestamptz not null default now()
);
create unique index plays_played_at_by_user on plays(user_id, spotify_id, played_at_minute);
create index plays_user on plays(user_id);
create index plays_played_at on plays(played_at);
create index plays_played_minute on plays(played_at_minute);
commit;