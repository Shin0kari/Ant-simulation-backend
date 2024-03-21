use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;

use super::list_of_status_code::OK_RESPONSE;

mod jwt_numeric_date {
    //! Custom serialization of OffsetDateTime to conform with the JWT spec (RFC 7519 section 2, "Numeric Date")
    use serde::{self, Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    /// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = date.unix_timestamp();
        serializer.serialize_i64(timestamp)
    }

    /// Attempts to deserialize an i32 and use as a Unix timestamp
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }
}

// поменять секретный ключ на что то более секретное
const KEY: &str = "secret";
pub const DB_URL: &str = "postgres://postgres:postgres@db:5432/postgres";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // email
    #[serde(with = "jwt_numeric_date")]
    pub iat: OffsetDateTime,
    #[serde(with = "jwt_numeric_date")]
    pub exp: OffsetDateTime,
    pub pswd: String, // мб это убрать, нужо будет спросить
    pub role: String,
}

impl Claims {
    // Проверка JWT
    pub fn verify_token(token: &str) -> Result<Claims, (String, serde_json::Value)> {
        let decoding_key = DecodingKey::from_secret(KEY.as_bytes());
        let validation = Validation::new(Algorithm::HS512);

        match decode::<Claims>(token, &decoding_key, &validation) {
            Ok(c) => Ok(c.claims),
            Err(err) => match *err.kind() {
                // сделать вывод ошибки
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    let response: serde_json::Value = json!({ "Error": "Token is invalid" });
                    Err((OK_RESPONSE.to_string(), response))
                } // Example on how to handle a specific error
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                    let response: serde_json::Value = json!({ "Error": "Issuer is invalid" });
                    Err((OK_RESPONSE.to_string(), response))
                } // Example on how to handle a specific error
                _ => {
                    let response: serde_json::Value =
                        json!({ "Error": "Having problems decoding the token" });
                    Err((OK_RESPONSE.to_string(), response))
                }
            },
        }
    }
}
