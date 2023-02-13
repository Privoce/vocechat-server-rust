alter table
    user
add
    column is_bot boolean not null default false;

alter table
    user_log
add
    column is_bot boolean;