create table third_party_users
(
    userid text primary key not null,
    uid    integer          not null,
    foreign key (uid) references user (uid) on delete cascade
);
