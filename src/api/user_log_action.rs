use poem_openapi::Enum;
use sqlx::sqlite::SqliteArgumentValue;

/// Update action type
#[derive(
    Debug, Copy, Clone, Eq, PartialEq, num_enum::IntoPrimitive, num_enum::TryFromPrimitive, Enum,
)]
#[repr(i32)]
#[oai(rename_all = "snake_case")]
pub enum UpdateAction {
    Create = 1,
    Update = 2,
    Delete = 3,
}

impl sqlx::Type<sqlx::Sqlite> for UpdateAction {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        i32::type_info()
    }

    fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
        i32::compatible(ty)
    }
}

impl<'a> sqlx::Decode<'a, sqlx::Sqlite> for UpdateAction {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'a>) -> Result<Self, sqlx::error::BoxDynError> {
        let n = i32::decode(value)?;
        Ok(Self::try_from(n)?)
    }
}

impl<'a> sqlx::Encode<'a, sqlx::Sqlite> for UpdateAction {
    fn encode_by_ref(
        &self,
        buf: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'a>>,
    ) -> sqlx::encode::IsNull {
        buf.push(SqliteArgumentValue::Int((*self).into()));
        sqlx::encode::IsNull::No
    }
}
