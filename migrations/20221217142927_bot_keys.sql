create table bot_key (
    id integer primary key autoincrement not null,
    uid integer not null,
    name string not null,
    key string not null,
    created_at timestamp not null default current_timestamp,
    last_used timestamp,
    foreign key (uid) references user (uid) on delete cascade
);

create index bot_key_uid on bot_key (uid);

create unique index bot_key_uid_name on bot_key (uid, name);