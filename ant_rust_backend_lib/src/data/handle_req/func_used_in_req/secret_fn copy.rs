use data_encoding::HEXUPPER;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use postgres::Client;
use ring::{digest, pbkdf2};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, num::NonZeroU32};
use time::{Duration, OffsetDateTime};

//
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
    pub pswd: String,
    pub role: String,
}

impl Claims {
    pub fn verify_token(token: &str) -> Result<Claims, (String, serde_json::Value)> {
        let key: &str = &get_env_data("KEY");
        let decoding_key = DecodingKey::from_secret(key.as_bytes());
        let validation = Validation::new(Algorithm::HS512);

        match decode::<Claims>(token, &decoding_key, &validation) {
            Ok(c) => Ok(c.claims),
            Err(err) => match *err.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => Err((
                    OK_RESPONSE.to_string(),
                    json!({ "Error": "Token is invalid" }),
                )),
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => Err((
                    OK_RESPONSE.to_string(),
                    json!({ "Error": "Issuer is invalid" }),
                )),
                _ => Err((
                    OK_RESPONSE.to_string(),
                    json!({ "Error": "Having problems decoding the token" }),
                )),
            },
        }
    }

    pub fn create_jwt_token(user: &User, user_info: &UserInfo) -> String {
        let key: &str = &get_env_data("KEY");
        let my_claims = Claims {
            sub: user.email.clone().unwrap().to_owned(),
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
            &EncodingKey::from_secret(key.as_bytes()),
        ) {
            Ok(t) => t,
            Err(err) => err.to_string(), // заменить ошибку
        };

        token
    }
}

pub fn get_env_data(key: &str) -> String {
    match env::var(key) {
        Ok(value) => value,
        Err(e) => {
            panic!("Error: {}", e);
        }
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
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
        };

        let salt = db.salt(user.email.as_ref().unwrap());
        let mut hash_pswd: Credential = [0u8; CREDENTIAL_LEN];
        pbkdf2::derive(
            PBKDF2_ALG,
            db.pbkdf2_iterations,
            &salt,
            user.pswd.as_ref().unwrap().as_bytes(),
            &mut hash_pswd, // pbkdf2_hash
        );

        HEXUPPER.encode(&hash_pswd)
    }

    pub fn verify_password(user: &User, client: &mut Client) -> bool {
        match client.query_one(
            "SELECT users.pswd FROM users WHERE users.email = $1",
            &[&user.email],
        ) {
            Ok(row) => {
                let actual_pswd: String = row.get(0);
                let hash_pswd = PasswordForDatabase::generate_hash_password(user);

                actual_pswd == hash_pswd
            }
            _ => false,
        }
    }

    fn salt(&self, email: &str) -> Vec<u8> {
        // можно изменить и добавить чтото для увеличения безопасности
        let mut salt = Vec::with_capacity(self.db_salt_component.len() + email.as_bytes().len());
        salt.extend(self.db_salt_component.as_ref());
        salt
    }
}
