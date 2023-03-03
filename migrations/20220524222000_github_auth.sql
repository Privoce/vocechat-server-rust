
create table github_auth
(
    username text primary key not null,
    uid   integer          not null,
    foreign key (uid) references user (uid) on delete cascade
);

create unique index github_auth_uid on github_auth (uid);