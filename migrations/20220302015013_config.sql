create table config
(
    name    text primary key,
    enabled bool not null default false,
    value   text not null
);
