use std::path::Path;

use parking_lot::Mutex;
use sled::Db;

use crate::{sequence::Sequence, Messages, Result};

const MSG_SEQUENCE: u8 = 1;

pub struct MsgDb {
    pub(crate) db: Db,
    msg_sequence: Mutex<Sequence>,
}

impl Drop for MsgDb {
    fn drop(&mut self) {
        self.msg_sequence.lock().release(&self.db);
    }
}

impl MsgDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = sled::open(path)?;
        let msg_sequence = Mutex::new(Sequence::new(&db, MSG_SEQUENCE)?);
        Ok(Self { db, msg_sequence })
    }

    #[inline]
    pub fn messages(&self) -> Messages {
        Messages { db: self }
    }

    pub(crate) fn generate_msg_id(&self) -> Result<i64> {
        self.msg_sequence.lock().generate_id(&self.db)
    }
}
