begin;
create table spot.tracks (
    id int8 primary key default spot.id_gen(),
    spotify_id text unique not null,
    name text not null,
    artist_names text[] not null,
    raw jsonb not null,
    created timestamptz not null default now(),
    modified timestamptz not null default now()
);
create index tracks_spotify_id on tracks(spotify_id);

alter table spot.plays
    add column artist_names text[] not null default '{}',
    drop column raw;
commit;