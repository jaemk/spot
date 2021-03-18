begin;
drop index auth_tokens_user;
drop index auth_tokens_hash;
drop index auth_tokens_expires;
drop table spot.auth_tokens;
commit;