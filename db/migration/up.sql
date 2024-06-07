create table users
(
    id       uuid default gen_random_uuid() not null
        constraint users_pk
            primary key,
    username varchar(20) not null,
    password varchar not null
);

create table refresh_tokens
(
    userid uuid not null
        constraint refresh_tokens_users_id_fk
            references users(id),
    token  varchar not null
);
