begin;
alter table spot.users
    drop column revoked;
commit;

