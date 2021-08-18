begin;
alter table spot.users
    add column revoked boolean not null default false;
commit;

