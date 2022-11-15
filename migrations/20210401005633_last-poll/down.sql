begin;
drop index users_last_poll;
drop index users_last_known_listen;

alter table spot.users
    drop column last_poll;
commit;