create table users (
    id int8 primary key default id_gen(),
    email text unique not null,
    name text not null,
    scopes text[] not null,
    access_token text not null,
    access_nonce text not null,
    refresh_token text not null,
    refresh_nonce text not null,
    access_expires int8 not null,
    auth_token text unique not null,
    created timestamptz not null default now(),
    modified timestamptz not null default now()
);