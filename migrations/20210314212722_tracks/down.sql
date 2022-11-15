begin;
alter table spot.plays
    drop column artist_names,
    add column raw jsonb;

drop index tracks_spotify_id;
drop table spot.tracks;
commit;
