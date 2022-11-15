begin;
alter table spot.users
    add column last_poll timestamptz;

create index users_last_poll on spot.users(last_poll);
create index users_last_known_listen on spot.users(last_known_listen);
commit;