use data_encoding::HEXUPPER;
use ring::{digest, pbkdf2};
use std::num::NonZeroU32;

use super::user_struct::User;

pub const DB_URL: &str = "postgres://postgres:postgres@db:5432/postgres";
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

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
