begin;
alter table spot.users
    add column poll_enabled boolean not null default false;

update spot.users
    set poll_enabled = true
    where email = 'james@kominick.com';
commit;

