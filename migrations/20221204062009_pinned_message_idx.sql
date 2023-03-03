drop index pinned_message_gid_mid;
create index pinned_message_gid_mid on pinned_message (gid, mid);
