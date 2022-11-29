use sled::Batch;

use crate::{MsgDb, Result};

pub struct Messages<'a> {
    pub(crate) db: &'a MsgDb,
}

impl<'a> Messages<'a> {
    pub fn get(&self, mid: i64) -> Result<Option<Vec<u8>>> {
        Ok(self.db.db.get(key_msg(mid))?.map(|data| data.to_vec()))
    }

    pub fn send_to_group(
        &self,
        gid: i64,
        to: impl IntoIterator<Item = i64>,
        msg: &[u8],
    ) -> Result<i64> {
        let id = self.db.generate_msg_id()?;
        let mut batch = Batch::default();
        batch.insert(&key_msg(id), msg);
        for target_uid in to {
            batch.insert(&key_user_msg(target_uid, id), msg);
        }
        batch.insert(&key_group_msg(gid, id), msg);
        self.db.db.apply_batch(batch)?;
        Ok(id)
    }

    pub fn send_to_dm(&self, from_uid: i64, to_uid: i64, msg: &[u8]) -> Result<i64> {
        let id = self.db.generate_msg_id()?;
        let mut batch = Batch::default();
        batch.insert(&key_msg(id), msg);
        for target_uid in [from_uid, to_uid] {
            batch.insert(&key_user_msg(target_uid, id), msg);
        }
        batch.insert(&key_dm_msg(from_uid, to_uid, id), msg);
        self.db.db.apply_batch(batch)?;
        Ok(id)
    }

    pub fn fetch_user_messages_after(
        &self,
        uid: i64,
        after: Option<i64>,
        limit: usize,
    ) -> Result<Vec<(i64, Vec<u8>)>> {
        let after_id = after.map(|id| id + 1).unwrap_or_default();
        let iter = self
            .db
            .db
            .range(key_user_msg(uid, after_id)..key_user_msg(uid, i64::MAX))
            .rev();
        let mut msgs = Vec::new();

        for item in iter.take(limit) {
            let (key, value) = item?;
            let (current_uid, msg_id) = match decode_key_user_msg(&key) {
                Some(res) => res,
                None => break,
            };

            if current_uid != uid {
                break;
            }

            msgs.push((msg_id, value.to_vec()));
        }

        msgs.reverse();
        Ok(msgs)
    }

    pub fn fetch_dm_messages_before(
        &self,
        from_uid: i64,
        to_uid: i64,
        before: Option<i64>,
        limit: usize,
    ) -> Result<Vec<(i64, Vec<u8>)>> {
        let before_id = before.unwrap_or(i64::MAX);
        let iter = self
            .db
            .db
            .range(key_dm_msg(from_uid, to_uid, 0)..key_dm_msg(from_uid, to_uid, before_id))
            .rev()
            .take(limit);
        let mut msgs = Vec::new();

        for item in iter {
            let (key, value) = item?;
            let (a, b, msg_id) = match decode_key_dm_msg(&key) {
                Some(res) => res,
                None => break,
            };

            if !(from_uid == a && to_uid == b || from_uid == b && to_uid == a) {
                break;
            }

            msgs.push((msg_id, value.to_vec()));
        }

        msgs.reverse();
        Ok(msgs)
    }

    pub fn fetch_group_messages_before(
        &self,
        gid: i64,
        before: Option<i64>,
        limit: usize,
    ) -> Result<Vec<(i64, Vec<u8>)>> {
        let before_id = before.unwrap_or(i64::MAX);
        let iter = self
            .db
            .db
            .range(key_group_msg(gid, 0)..key_group_msg(gid, before_id))
            .rev()
            .take(limit);
        let mut msgs = Vec::new();

        for item in iter {
            let (key, value) = item?;
            let (current_gid, msg_id) = match decode_key_group_msg(&key) {
                Some(res) => res,
                None => break,
            };

            if current_gid != gid {
                break;
            }

            msgs.push((msg_id, value.to_vec()));
        }

        msgs.reverse();
        Ok(msgs)
    }

    pub fn insert_merged_msg(&self, mid: i64, msg: &[u8]) -> Result<()> {
        self.db.db.insert(key_merged_msg(mid), msg)?;
        Ok(())
    }

    pub fn update_merged_msg(&self, mid: i64, mut f: impl FnMut(&[u8]) -> Vec<u8>) -> Result<()> {
        self.db
            .db
            .update_and_fetch(key_merged_msg(mid), |data| data.map(&mut f))?;
        Ok(())
    }

    pub fn remove_merged_msg(&self, mid: i64) -> Result<()> {
        self.db.db.remove(key_merged_msg(mid))?;
        Ok(())
    }

    pub fn get_merged_msg(&self, mid: i64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db
            .db
            .get(key_merged_msg(mid))?
            .map(|data| data.to_vec()))
    }
}

fn key_msg(msg_id: i64) -> [u8; 12] {
    let mut data = [0; 12];
    data[0..4].copy_from_slice(b"MSG/");
    data[4..12].copy_from_slice(&msg_id.to_be_bytes());
    data
}

fn key_merged_msg(msg_id: i64) -> [u8; 13] {
    let mut data = [0; 13];
    data[0..5].copy_from_slice(b"FMSG/");
    data[5..13].copy_from_slice(&msg_id.to_be_bytes());
    data
}

fn key_user_msg(uid: i64, msg_id: i64) -> [u8; 21] {
    let mut data = [0; 21];
    data[0..5].copy_from_slice(b"UMSG/");
    data[5..13].copy_from_slice(&uid.to_be_bytes());
    data[13..21].copy_from_slice(&msg_id.to_be_bytes());
    data
}

fn decode_key_user_msg(data: &[u8]) -> Option<(i64, i64)> {
    let data = data.strip_prefix(b"UMSG/")?;
    if data.len() != 16 {
        return None;
    }
    let uid = i64::from_be_bytes(data[0..8].try_into().unwrap());
    let msg_id = i64::from_be_bytes(data[8..16].try_into().unwrap());
    Some((uid, msg_id))
}

fn key_group_msg(gid: i64, msg_id: i64) -> [u8; 21] {
    let mut data = [0; 21];
    data[0..5].copy_from_slice(b"GMSG/");
    data[5..13].copy_from_slice(&gid.to_be_bytes());
    data[13..21].copy_from_slice(&msg_id.to_be_bytes());
    data
}

fn decode_key_group_msg(data: &[u8]) -> Option<(i64, i64)> {
    let data = data.strip_prefix(b"GMSG/")?;
    if data.len() != 16 {
        return None;
    }
    let gid = i64::from_be_bytes(data[0..8].try_into().unwrap());
    let msg_id = i64::from_be_bytes(data[8..16].try_into().unwrap());
    Some((gid, msg_id))
}

fn key_dm_msg(from_uid: i64, to_uid: i64, msg_id: i64) -> [u8; 27] {
    let mut data = [0; 27];
    let a = from_uid.min(to_uid);
    let b = from_uid.max(to_uid);
    data[0..3].copy_from_slice(b"DM/");
    data[3..11].copy_from_slice(&a.to_be_bytes());
    data[11..19].copy_from_slice(&b.to_be_bytes());
    data[19..27].copy_from_slice(&msg_id.to_be_bytes());
    data
}

fn decode_key_dm_msg(data: &[u8]) -> Option<(i64, i64, i64)> {
    let data = data.strip_prefix(b"DM/")?;
    if data.len() != 24 {
        return None;
    }
    let from_uid = i64::from_be_bytes(data[0..8].try_into().unwrap());
    let to_uid = i64::from_be_bytes(data[8..16].try_into().unwrap());
    let msg_id = i64::from_be_bytes(data[16..24].try_into().unwrap());
    Some((from_uid, to_uid, msg_id))
}
