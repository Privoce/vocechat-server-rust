use sled::Db;

use crate::{Error, Result};

const SEQUENCE_BANDWIDTH: i64 = 32;

pub(crate) struct Sequence {
    ty: u8,
    next: i64,
    leased: i64,
}

impl Sequence {
    pub(crate) fn new(db: &Db, ty: u8) -> Result<Sequence> {
        let (next, leased) = Self::update_sequence_lease(ty, db)?;
        Ok(Sequence { ty, next, leased })
    }

    pub(crate) fn release(&self, db: &Db) {
        let _ = db.insert(key_sequence(self.ty), &self.next.to_be_bytes());
    }

    fn update_sequence_lease(ty: u8, db: &Db) -> Result<(i64, i64)> {
        let key = key_sequence(ty);
        let next = match db.get(key)? {
            Some(value) => {
                i64::from_be_bytes(value.as_ref().try_into().map_err(|_| Error::InvalidData)?)
            }
            None => 1,
        };
        let leased = next + SEQUENCE_BANDWIDTH;
        db.insert(key, &leased.to_be_bytes())?;
        Ok((next, leased))
    }

    pub(crate) fn generate_id(&mut self, db: &Db) -> Result<i64> {
        if self.next >= self.leased {
            let (next, lease) = Self::update_sequence_lease(self.ty, db)?;
            self.next = next;
            self.leased = lease;
        }
        let val = self.next;
        self.next += 1;
        Ok(val)
    }
}

fn key_sequence(ty: u8) -> [u8; 10] {
    let mut data = [0; 10];
    data[0..9].copy_from_slice(b"SEQUENCE/");
    data[9] = ty;
    data
}
