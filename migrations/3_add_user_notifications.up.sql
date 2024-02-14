create table if not exists public.user_notifications (
    id bigserial constraint user_notifications_pk primary key,
    user_id bigint not null,
    type text not null,
    code text not null,
    created_at timestamp not null
)