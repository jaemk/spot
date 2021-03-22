begin;
alter table spot.users
    add column last_known_listen timestamptz;

alter table spot.plays
    add column last_known_listen timestamptz;
commit;