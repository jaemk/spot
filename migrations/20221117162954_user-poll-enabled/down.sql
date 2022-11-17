begin;
alter table spot.users
    drop column poll_enabled;
commit;

