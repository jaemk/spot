begin;
create table spot.auth_tokens (
    id int8 primary key not null default spot.id_gen(),
    hash text unique not null,
    user_id int8 not null references spot.users(id) on delete cascade,
    expires timestamptz not null,
    created timestamptz not null default now(),
    modified timestamptz not null default now()
);
create index auth_tokens_hash on spot.auth_tokens(hash);
create index auth_tokens_user on spot.auth_tokens(user_id);
create index auth_tokens_expires on spot.auth_tokens(expires);
commit;