create table if not exists public.users
(
    id              bigserial constraint users_pk primary key,
    auth_system     text,
    sub             text,
    name            text  not null,
    given_name      text,
    family_name     text,
    avatar          text,
    email           text  not null,
    email_verified  bool  not null default false,
    locale          varchar(5),
    hashed_password bytea,
    role            text  not null
);