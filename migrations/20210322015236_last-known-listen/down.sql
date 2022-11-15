begin;
alter table spot.plays
    drop column last_known_listen;

alter table spot.users
    drop column last_known_listen;
commit;