/* работа с jwt token
// use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};

// // Создание JWT
// fn create_token() -> String {
//     let header = Header::default();
//     let claims = MyClaims {
//         sub: "example_user".to_string(),
//     }; // Ваши данные
//     let token = encode(
//         &header,
//         &claims,
//         &EncodingKey::from_secret("secret_key".as_ref()),
//     )
//     .unwrap();
//     println!("JWT: {}", token);
//     token
// }

// Проверка JWT
fn verify_token(token: &str) {
    let decoding_key = DecodingKey::from_secret("secret_key".as_ref());
    let validation = Validation::default();
    let token_data: TokenData<MyClaims> = decode(token, &decoding_key, &validation);
    println!("User: {}", token_data.claims.sub);
    // Можно проверять другие данные, доступные в token_data
}

// #[macro_use]
// extern crate serde_derive;

// #[derive(Debug, Serialize, Deserialize)]
// struct MyClaims {
//     sub: String, // Идентификатор пользователя
//                  // Другие поля
// }

// fn main() {
//     let mut token = create_token();
//     verify_token(&token);
// }
// use postgres::types::ToSql;
*/

use ring::{digest, pbkdf2};
use std::num::NonZeroU32;

use data_encoding::HEXUPPER;
use postgres::Error as PostgresError;
use postgres::{Client, NoTls};
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[macro_use]
extern crate serde_derive;

#[derive(Serialize, Deserialize)]
struct User {
    id: Option<i32>,
    name: Option<String>,
    pswd: Option<String>,
    email: Option<String>,
}

const DB_URL: &str = env!("DATABASE_URL");
// const DB_URL: &str = "postgres://postgres:postgres@db:5432/postgres";

const OK_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
const NOT_FOUND_RESPONSE: &str = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
const INTERNAL_SERVER_ERROR: &str = "HTTP/1.1 500 INTERNAL SERVER ERROR\r\n\r\n";

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

enum Error {
    WrongUsernameOrPassword,
}

struct PasswordForDatabase {
    pbkdf2_iterations: NonZeroU32,
    db_salt_component: [u8; 16],
}

impl PasswordForDatabase {
    pub fn generate_hash_password(&mut self, user: &User, client: &mut Client) -> String {
        let salt = self.salt(&user.name.as_ref().unwrap());
        let mut hash_pswd: Credential = [0u8; CREDENTIAL_LEN];
        pbkdf2::derive(
            PBKDF2_ALG,
            self.pbkdf2_iterations,
            &salt,
            user.pswd.as_ref().unwrap().as_bytes(),
            &mut hash_pswd, // pbkdf2_hash
        );

        HEXUPPER.encode(&hash_pswd)
    }

    pub fn verify_password(&self, user: &User, mut client: &mut Client) -> bool {
        match client.query_one(
            "SELECT users.pswd FROM users WHERE users.email = $1",
            &[&user.email],
        ) {
            Ok(row) => {
                let mut db = PasswordForDatabase {
                    pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                    db_salt_component: [
                        // This value was generated from a secure PRNG.
                        0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                        0xfe, 0x39, 0x01, 0x8a,
                    ],
                };

                let mut actual_pswd: String = row.get(0);
                let mut hash_pswd = db.generate_hash_password(&user, &mut client);

                if actual_pswd == hash_pswd {
                    true
                } else {
                    false
                }
            }
            _ => false,
        }

        // получаем от пользователя истинный хешированный пароль, хешируем пароль введённый пользователем, сравниваем

        // match self.storage.get(username) {
        //     Some(actual_password) => {
        //         let salt = self.salt(username);
        //         pbkdf2::verify(
        //             PBKDF2_ALG,
        //             self.pbkdf2_iterations,
        //             &salt,
        //             attempted_password.as_bytes(),
        //             actual_password,
        //         )
        //         .map_err(|_| Error::WrongUsernameOrPassword)
        //     }

        //     None => Err(Error::WrongUsernameOrPassword),
        // }
    }

    fn salt(&self, username: &str) -> Vec<u8> {
        let mut salt = Vec::with_capacity(self.db_salt_component.len() + username.as_bytes().len());
        salt.extend(self.db_salt_component.as_ref());
        salt.extend(username.as_bytes());
        salt
    }
}

fn main() {
    if let Err(e) = set_database() {
        println!("Error: {}", e);
        return;
    }

    let listener = TcpListener::bind(format!("0.0.0.0:8080")).unwrap();
    println!("Server started at port 8080");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Обработка каждого клиента в отдельном потоке
                std::thread::spawn(|| {
                    // обработка подключения
                    handle_client(stream);
                });
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}

fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    let mut request = String::new();

    match stream.read(&mut buffer) {
        Ok(size) => {
            request.push_str(String::from_utf8_lossy(&buffer[..size]).as_ref());

            let (status_line, content) = match &*request {
                r if r.starts_with("POST /users") => handle_sign_up_request(r),
                r if r.starts_with("GET /users/") => handle_get_request(r),
                r if r.starts_with("GET /users") => handle_get_all_request(r),
                r if r.starts_with("PUT /users/") => handle_put_request(r),
                r if r.starts_with("DELETE /users/") => handle_delete_request(r),
                _ => (
                    NOT_FOUND_RESPONSE.to_string(),
                    "Not found response".to_string(),
                ),
            };

            stream
                .write_all(format!("{}{}", status_line, content).as_bytes())
                .unwrap();
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}

/* post request
fn handle_post_request(request: &str) -> (String, String) {
    match (
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(user), Ok(mut client)) => {
            client
                .execute(
                    "INSERT INTO users (name, email) VALUES ($1, $2)",
                    &[&user.name, &user.email],
                )
                .unwrap();

            (OK_RESPONSE.to_string(), "User created".to_string())
        }
        _ => (INTERNAL_SERVER_ERROR.to_string(), "Error".to_string()),
    }
}
*/
fn handle_sign_in_request(request: &str) -> (String, String) {
    match (
        get_id(&request).parse::<i32>(),
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(id), Ok(user), Ok(mut client)) => {
            match client.query_one(
                "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                &[&user.email],
            ) {
                Ok(row) => {
                    let mut db = PasswordForDatabase {
                        pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                        db_salt_component: [
                            // This value was generated from a secure PRNG.
                            0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                            0xfe, 0x39, 0x01, 0x8a,
                        ],
                    };

                    let user_email_presence: bool = row.get(0);
                    if user_email_presence == true {
                        let mut verification = db.verify_password(&user, &mut client);

                        if verification == true {
                            // create jws token

                            (
                                OK_RESPONSE.to_string(),
                                "The user is authorized".to_string(),
                            )
                        } else {
                            (
                                OK_RESPONSE.to_string(),
                                "Wrong email or password".to_string(),
                            )
                        }
                    } else {
                        (
                            OK_RESPONSE.to_string(), // изменить на другу ошибку
                            "There is no user with this email".to_string(),
                        )
                    }
                }
                _ => (
                    NOT_FOUND_RESPONSE.to_string(),
                    "Error creating initial table".to_string(),
                ),
            }
        }

        _ => (INTERNAL_SERVER_ERROR.to_string(), "Error".to_string()),
    }
}

fn handle_sign_up_request(request: &str) -> (String, String) {
    match (
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(user), Ok(mut client)) => {
            match client.query_one(
                "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                &[&user.email],
            ) {
                Ok(row) => {
                    let mut db = PasswordForDatabase {
                        pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                        db_salt_component: [
                            // This value was generated from a secure PRNG.
                            0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                            0xfe, 0x39, 0x01, 0x8a,
                        ],
                    };

                    let user_email_presence: bool = row.get(0);
                    if user_email_presence == false {
                        // генерируем хеш ключ и заносим в бд
                        let mut hash_pswd = db.generate_hash_password(&user, &mut client);

                        client
                            .execute(
                                "INSERT INTO users (name, pswd, email) VALUES ($1, $2, $3)",
                                &[&user.name, &hash_pswd, &user.email],
                            )
                            .unwrap();

                        (OK_RESPONSE.to_string(), "User registered".to_string())
                    } else {
                        (
                            OK_RESPONSE.to_string(),
                            "This email is already taken".to_string(),
                        )
                    }
                }
                _ => (
                    NOT_FOUND_RESPONSE.to_string(),
                    "Error creating initial table".to_string(),
                ),
            }
        }
        _ => (INTERNAL_SERVER_ERROR.to_string(), request.to_string()),
    }
}

fn handle_get_request(request: &str) -> (String, String) {
    match (
        get_id(&request).parse::<i32>(),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(id), Ok(mut client)) => {
            match client.query_one("SELECT * FROM users WHERE id = $1", &[&id]) {
                Ok(row) => {
                    let user = User {
                        id: row.get(0),
                        name: row.get(1),
                        pswd: row.get(2),
                        email: row.get(3),
                    };

                    (
                        OK_RESPONSE.to_string(),
                        serde_json::to_string(&user).unwrap(),
                    )
                }
                _ => (NOT_FOUND_RESPONSE.to_string(), "User not found".to_string()),
            }
        }

        _ => (INTERNAL_SERVER_ERROR.to_string(), "Error".to_string()),
    }
}

fn handle_get_all_request(_request: &str) -> (String, String) {
    match Client::connect(DB_URL, NoTls) {
        Ok(mut client) => {
            let mut users = Vec::new();

            for row in client.query("SELECT * FROM users", &[]).unwrap() {
                users.push(User {
                    id: row.get(0),
                    name: row.get(1),
                    pswd: row.get(2),
                    email: row.get(3),
                });
            }

            (
                OK_RESPONSE.to_string(),
                serde_json::to_string(&users).unwrap(),
            )
        }

        _ => (INTERNAL_SERVER_ERROR.to_string(), "Error".to_string()),
    }
}

fn handle_put_request(request: &str) -> (String, String) {
    match (
        get_id(&request).parse::<i32>(),
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(id), Ok(user), Ok(mut client)) => {
            match client.query_one(
                "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                &[&user.email],
            ) {
                Ok(row) => {
                    let mut db = PasswordForDatabase {
                        pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                        db_salt_component: [
                            // This value was generated from a secure PRNG.
                            0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                            0xfe, 0x39, 0x01, 0x8a,
                        ],
                    };

                    let user_presence: bool = row.get(0);
                    if user_presence == false {
                        let mut hash_pswd = db.generate_hash_password(&user, &mut client);

                        client
                            .execute(
                                "UPDATE users SET (name, pswd, email) VALUES ($1, $2, $3) WHERE id = $4",
                                &[&user.name, &hash_pswd, &user.email, &id],
                            )
                            .unwrap();

                        (OK_RESPONSE.to_string(), "User updated".to_string())
                    } else {
                        (
                            OK_RESPONSE.to_string(), // изменить на другу ошибку
                            "This email is already taken".to_string(),
                        )
                    }
                }
                _ => (
                    NOT_FOUND_RESPONSE.to_string(),
                    "Error creating initial table".to_string(),
                ),
            }
        }

        _ => (INTERNAL_SERVER_ERROR.to_string(), "Error".to_string()),
    }
}

fn handle_delete_request(request: &str) -> (String, String) {
    match (
        get_id(&request).parse::<i32>(),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(id), Ok(mut client)) => {
            let rows_affected = client
                .execute("DELETE FROM users WHERE id = $1", &[&id])
                .unwrap();

            if rows_affected == 9 {
                return (NOT_FOUND_RESPONSE.to_string(), "User not found".to_string());
            }

            (OK_RESPONSE.to_string(), "User deleted".to_string())
        }

        _ => (INTERNAL_SERVER_ERROR.to_string(), "Error".to_string()),
    }
}

fn set_database() -> Result<(), PostgresError> {
    let mut client = Client::connect(DB_URL, NoTls)?;

    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR NOT NULL,
            pswd BYTEA NOT NULL,
            email VARCHAR NOT NULL
        )",
    )?;
    Ok(())
}

// Получение id из запроса
fn get_id(request: &str) -> &str {
    request
        .split("/")
        .nth(2)
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or_default()
}

fn get_user_request_body(request: &str) -> Result<User, serde_json::Error> {
    serde_json::from_str(request.split("\r\n\r\n").last().unwrap_or_default())
}

/* для хеширования паролей

// extern crate data_encoding;
// extern crate ring;

// use data_encoding::HEXUPPER;
// use ring::error::Unspecified;
// use ring::rand::SecureRandom;
// use ring::{digest, pbkdf2, rand};
// use std::num::NonZeroU32;

// fn main() -> Result<(), Unspecified> {
//     const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
//     let n_iter = NonZeroU32::new(100_000).unwrap();
//     let rng = rand::SystemRandom::new();

//     let mut salt = [0u8; CREDENTIAL_LEN];
//     rng.fill(&mut salt)?;

//     let password = "Guess Me If You Can!";
//     let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];

//     pbkdf2::derive(
//         pbkdf2::PBKDF2_HMAC_SHA512,
//         n_iter,
//         &salt,
//         password.as_bytes(),
//         &mut pbkdf2_hash,
//     );
//     println!("Salt: {}", HEXUPPER.encode(&salt));
//     println!("PBKDF2 hash pswd: {}", HEXUPPER.encode(&pbkdf2_hash));

//     let should_succeed = pbkdf2::verify(
//         pbkdf2::PBKDF2_HMAC_SHA512,
//         n_iter,
//         &salt,
//         password.as_bytes(),
//         &pbkdf2_hash,
//     );

//     let wrong_password = "Definitely not the correct password";
//     pbkdf2::derive(
//         pbkdf2::PBKDF2_HMAC_SHA512,
//         n_iter,
//         &salt,
//         wrong_password.as_bytes(),
//         &mut pbkdf2_hash,
//     );
//     println!("PBKDF2 hash wrong pswd: {}", HEXUPPER.encode(&pbkdf2_hash));

//     pbkdf2::derive(
//         pbkdf2::PBKDF2_HMAC_SHA512,
//         n_iter,
//         &salt,
//         password.as_bytes(),
//         &mut pbkdf2_hash,
//     );
//     println!(
//         "PBKDF2 hash pswd after wrong: {}",
//         HEXUPPER.encode(&pbkdf2_hash)
//     );

//     let should_fail = pbkdf2::verify(
//         pbkdf2::PBKDF2_HMAC_SHA512,
//         n_iter,
//         &salt,
//         wrong_password.as_bytes(),
//         &pbkdf2_hash,
//     );

//     assert!(should_succeed.is_ok());
//     assert!(!should_fail.is_ok());

//     Ok(())
// }

*/
