use std::{borrow::Cow, ops::Deref};

use chrono::{TimeZone, Utc};
use poem_openapi::registry::{MetaSchema, MetaSchemaRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct DateTime(pub chrono::DateTime<Utc>);

impl DateTime {
    #[inline]
    pub fn now() -> Self {
        Self(Utc::now())
    }

    pub fn zero() -> Self {
        Self(Utc.timestamp_millis_opt(0).unwrap())
    }
}

impl From<chrono::DateTime<Utc>> for DateTime {
    fn from(datetime: chrono::DateTime<Utc>) -> Self {
        Self(datetime)
    }
}

impl From<DateTime> for chrono::DateTime<Utc> {
    fn from(datetime: DateTime) -> Self {
        datetime.0
    }
}

impl Deref for DateTime {
    type Target = chrono::DateTime<Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for DateTime {
    fn default() -> Self {
        Self(Utc::now())
    }
}

impl sqlx::Type<sqlx::Sqlite> for DateTime {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <chrono::DateTime<Utc>>::type_info()
    }

    fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
        <chrono::DateTime<Utc>>::compatible(ty)
    }
}

impl<'a> sqlx::Decode<'a, sqlx::Sqlite> for DateTime {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'a>) -> Result<Self, sqlx::error::BoxDynError> {
        <chrono::DateTime<Utc>>::decode(value).map(Self)
    }
}

impl<'a> sqlx::Encode<'a, sqlx::Sqlite> for DateTime {
    fn encode_by_ref(
        &self,
        buf: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'a>>,
    ) -> sqlx::encode::IsNull {
        self.0.encode(buf)
    }
}

impl poem_openapi::types::Type for DateTime {
    const IS_REQUIRED: bool = true;
    type RawValueType = Self;
    type RawElementValueType = Self;

    fn name() -> Cow<'static, str> {
        "integer(timestamp)".into()
    }

    fn schema_ref() -> poem_openapi::registry::MetaSchemaRef {
        MetaSchemaRef::Inline(Box::new(MetaSchema::new_with_format(
            "integer",
            "timestamp",
        )))
    }

    fn as_raw_value(&self) -> Option<&Self::RawValueType> {
        Some(self)
    }

    fn raw_element_iter<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = &'a Self::RawElementValueType> + 'a> {
        Box::new(self.as_raw_value().into_iter())
    }
}

impl poem_openapi::types::ParseFromJSON for DateTime {
    fn parse_from_json(value: Option<Value>) -> poem_openapi::types::ParseResult<Self> {
        i64::parse_from_json(value)
            .map(|timestamp| Self(Utc.timestamp_millis_opt(timestamp).unwrap()))
            .map_err(poem_openapi::types::ParseError::propagate)
    }
}

impl poem_openapi::types::ToJSON for DateTime {
    fn to_json(&self) -> Option<Value> {
        Some(self.0.timestamp_millis().into())
    }
}
