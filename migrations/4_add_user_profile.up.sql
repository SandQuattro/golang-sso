create table if not exists public.user_profile_settings
(
    id            bigserial constraint user_profile_settings_pk primary key,
    user_id       bigint not null unique,
    send_messages int    not null default 0
);