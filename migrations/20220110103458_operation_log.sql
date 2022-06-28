create table operation_log
(
    id integer primary key autoincrement not null,
    log text not null,
    created_at timestamp not null default current_timestamp
);
