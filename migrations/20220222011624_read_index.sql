create table read_index
(
    id         integer primary key autoincrement not null,
    uid        integer not null,
    target_uid integer,
    target_gid integer,
    mid        integer not null,
    foreign key (uid) references user (uid) on delete cascade,
    foreign key (target_uid) references `user` (uid) on delete cascade,
    foreign key (target_gid) references `group` (gid) on delete cascade
);

create unique index read_index_uid_uid on read_index (uid, target_uid);
create unique index read_index_uid_gid on read_index (uid, target_gid);
create index read_index_uid on read_index (uid);
