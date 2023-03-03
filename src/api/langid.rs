use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
    ops::Deref,
    str::FromStr,
};

use poem_openapi::registry::{MetaSchema, MetaSchemaRef};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sqlx::sqlite::SqliteArgumentValue;

/// Language id
///
/// Reference: <http://tools.ietf.org/html/bcp47>
#[derive(Debug, Clone)]
pub struct LangId(unic_langid::LanguageIdentifier);

impl Default for LangId {
    fn default() -> Self {
        Self("en-US".parse().unwrap())
    }
}

impl Display for LangId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for LangId {
    type Err = unic_langid::LanguageIdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        unic_langid::LanguageIdentifier::from_str(s).map(Self)
    }
}

impl Deref for LangId {
    type Target = unic_langid::LanguageIdentifier;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl sqlx::Type<sqlx::Sqlite> for LangId {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        String::type_info()
    }

    fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
        String::compatible(ty)
    }
}

impl<'a> sqlx::Decode<'a, sqlx::Sqlite> for LangId {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'a>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = String::decode(value)?;
        let language_tag: unic_langid::LanguageIdentifier = s.parse().map_err(Box::new)?;
        Ok(Self(language_tag))
    }
}

impl<'a> sqlx::Encode<'a, sqlx::Sqlite> for LangId {
    fn encode_by_ref(
        &self,
        buf: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'a>>,
    ) -> sqlx::encode::IsNull {
        buf.push(SqliteArgumentValue::Text(Cow::Owned(self.0.to_string())));
        sqlx::encode::IsNull::No
    }
}

impl poem_openapi::types::Type for LangId {
    const IS_REQUIRED: bool = true;
    type RawValueType = Self;
    type RawElementValueType = Self;

    fn name() -> Cow<'static, str> {
        Cow::Borrowed("string(language)")
    }

    fn schema_ref() -> MetaSchemaRef {
        MetaSchemaRef::Inline(Box::new(MetaSchema::new_with_format("string", "language")))
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

impl poem_openapi::types::ParseFromJSON for LangId {
    fn parse_from_json(value: Option<Value>) -> poem_openapi::types::ParseResult<Self> {
        let value = value.unwrap_or_default();
        match &value {
            Value::String(s) => unic_langid::LanguageIdentifier::from_str(s)
                .map(Self)
                .map_err(poem_openapi::types::ParseError::custom),
            _ => Err(poem_openapi::types::ParseError::expected_type(value)),
        }
    }
}

impl poem_openapi::types::ToJSON for LangId {
    fn to_json(&self) -> Option<Value> {
        Some(Value::String(self.0.to_string()))
    }
}

impl Serialize for LangId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for LangId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        LangId::from_str(&s).map_err(|err| <D::Error>::custom(err.to_string()))
    }
}
