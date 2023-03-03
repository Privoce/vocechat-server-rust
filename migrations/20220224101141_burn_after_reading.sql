create table burn_after_reading
(
    id         integer primary key autoincrement not null,
    uid        integer not null,
    target_uid integer,
    target_gid integer,
    expires_in integer not null,
    foreign key (uid) references user (uid) on delete cascade,
    foreign key (target_uid) references `user` (uid) on delete cascade,
    foreign key (target_gid) references `group` (gid) on delete cascade
);

create unique index burn_after_reading_uid_uid on burn_after_reading (uid, target_uid);
create unique index burn_after_reading_uid_gid on burn_after_reading (uid, target_gid);
create index burn_after_reading_uid on burn_after_reading (uid);
