create table metamask_auth
(
    public_address text primary key not null,
    uid            integer          not null,
    foreign key (uid) references user (uid) on delete cascade
);

create unique index metamask_auth_uid on metamask_auth (uid);

create table metamask_nonce
(
    public_address text primary key not null,
    nonce          text             not null
);
