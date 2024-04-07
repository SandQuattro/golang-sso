create table if not exists public.tokens
(
    id            bigserial constraint tokens_pk primary key,
    user_id       bigint not null,
    token         text    not null,
    expired_at    timestamp not null,
    created_at    timestamp not null
);