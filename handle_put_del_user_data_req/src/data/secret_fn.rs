use data_encoding::HEXUPPER;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use ring::{digest, pbkdf2};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::num::NonZeroU32;
use time::{Duration, OffsetDateTime};

use super::{
    list_of_status_code::OK_RESPONSE,
    user_struct::{User, UserInfo},
};

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
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

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

    // если меняется одно из aud(email), pswd, role то создаём заново токен для пользователя< (No self?)
    pub fn create_jwt_token(user: &User, user_info: &UserInfo) -> String {
        let my_claims = Claims {
            sub: user.email.clone().unwrap().to_owned(),
            // aud: user.email.clone().unwrap().to_owned(),
            iat: OffsetDateTime::now_utc(),
            exp: OffsetDateTime::now_utc() + Duration::days(1),
            pswd: user.pswd.clone().unwrap().to_owned(),
            role: user_info.role.clone().unwrap().to_owned(),
        };

        let header = Header {
            alg: Algorithm::HS512,
            ..Default::default()
        };

        let token = match encode(
            &header,
            &my_claims,
            &EncodingKey::from_secret(KEY.as_bytes()),
        ) {
            Ok(t) => t,
            Err(err) => err.to_string(), // in practice you would return the error
        };

        token
    }
}

pub struct PasswordForDatabase {
    pbkdf2_iterations: NonZeroU32,
    db_salt_component: [u8; 16],
}

impl PasswordForDatabase {
    pub fn generate_hash_password(user: &User) -> String {
        let db = PasswordForDatabase {
            pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
            // нужно сгенерировать новый
            db_salt_component: [
                // This value was generated from a secure PRNG.
                0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1, 0xfe, 0x39,
                0x01, 0x8a,
            ],
        };

        let salt = db.salt(user.email.as_ref().unwrap());
        let mut hash_pswd: Credential = [0u8; CREDENTIAL_LEN];
        // unwrap заменить на match (где точное не будет None там можно оставить unwrap с комментарием)
        pbkdf2::derive(
            PBKDF2_ALG,
            db.pbkdf2_iterations,
            &salt,
            user.pswd.as_ref().unwrap().as_bytes(),
            &mut hash_pswd, // pbkdf2_hash
        );

        HEXUPPER.encode(&hash_pswd)
    }

    // возможно генерацию соли нужно убрать в скрытый файл для безопасности
    fn salt(&self, email: &str) -> Vec<u8> {
        let mut salt = Vec::with_capacity(self.db_salt_component.len() + email.as_bytes().len());
        salt.extend(self.db_salt_component.as_ref());
        salt
    }
}
