CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

create table users
(
    id       uuid default uuid_generate_v4() not null
        constraint users_pk
            primary key,
    username varchar(20) not null,
    password varchar not null
);

create table refresh_tokens
(
    user_id uuid not null unique
        constraint refresh_tokens_users_id_fk
            references users(id),
    token  varchar not null,
    access_token_id varchar not null,
    used boolean default false not null
);
