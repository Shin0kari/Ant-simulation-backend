use ring::{digest, pbkdf2};

use std::num::NonZeroU32;

use data_encoding::HEXUPPER;
use postgres::Error as PostgresError;
use postgres::{Client, NoTls};
// use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use time::{Duration, OffsetDateTime};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String, // email
    #[serde(with = "jwt_numeric_date")]
    iat: OffsetDateTime,
    #[serde(with = "jwt_numeric_date")]
    exp: OffsetDateTime,
    pswd: String, // мб это убрать, нужо будет спросить
    role: String,
}

impl Claims {
    // проблема, что при изменении email не проходит верификацию
    // Проверка JWT
    pub fn verify_token(token: &str, user: &User) -> Result<Claims, std::io::Error> {
        let decoding_key = DecodingKey::from_secret(KEY.as_bytes());
        let mut validation = Validation::new(Algorithm::HS512);
        validation.set_audience(&[user.email.clone().unwrap().as_str()]);

        let token_data = match decode::<Claims>(&token, &decoding_key, &validation) {
            Ok(c) => c,
            Err(err) => match *err.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => panic!("Token is invalid"), // Example on how to handle a specific error
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => panic!("Issuer is invalid"), // Example on how to handle a specific error
                _ => panic!("Some other errors"),
            },
        };

        // let token_data = match decode::<Claims>(&token.to_string(), &decoding_key, &validation) {
        //     Ok(c) => c,
        //     Err(err) => match *err.kind() {
        //         jsonwebtoken::errors::ErrorKind::InvalidToken => panic!(), // Example on how to handle a specific error
        //         _ => panic!(),
        //     },
        // };

        Ok(token_data.claims)
        // Можно проверять другие данные, доступные в token_data
    }

    // если меняется одно из aud(email), pswd, role то создаём заново токен для пользователя
    pub fn create_jwt_token(user: &User) -> String {
        let my_claims = Claims {
            aud: user.email.clone().unwrap().to_owned(),
            iat: OffsetDateTime::now_utc(),
            exp: OffsetDateTime::now_utc() + Duration::days(1),
            pswd: user.pswd.clone().unwrap().to_owned(),
            role: user.role.clone().unwrap().to_owned(),
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
            Err(_) => panic!(), // in practice you would return the error
        };

        token
    }
}

// поменять секретный ключ на что то более секретное
const KEY: &str = "secret";

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

    /// Attempts to deserialize an i64 and use as a Unix timestamp
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: Option<i32>,
    role: Option<String>,
    name: Option<String>,
    pswd: Option<String>,
    email: Option<String>,
}

// impl User {
//     fn request_body_sign_up() {}
// }

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

// enum Error {
//     WrongUsernameOrPassword,
// }

struct PasswordForDatabase {
    pbkdf2_iterations: NonZeroU32,
    db_salt_component: [u8; 16],
}

impl PasswordForDatabase {
    pub fn generate_hash_password(&mut self, user: &User) -> String {
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

    pub fn verify_password(&self, user: &User, client: &mut Client) -> bool {
        // добавить проверку подключения к бд
        match client.query_one(
            "SELECT users.pswd FROM users WHERE users.email = $1",
            &[&user.email],
        ) {
            Ok(row) => {
                let mut db = PasswordForDatabase {
                    pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                    // нужно сгенерировать новый
                    db_salt_component: [
                        // This value was generated from a secure PRNG.
                        0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                        0xfe, 0x39, 0x01, 0x8a,
                    ],
                };

                let actual_pswd: String = row.get(0);
                let hash_pswd = db.generate_hash_password(&user);

                actual_pswd == hash_pswd
            }
            _ => false,
        }
    }

    // возможно генерацию соли нужно убрать в скрытый файл для безопасности
    fn salt(&self, username: &str) -> Vec<u8> {
        let mut salt = Vec::with_capacity(self.db_salt_component.len() + username.as_bytes().len());
        salt.extend(self.db_salt_component.as_ref());
        salt.extend(username.as_bytes());
        salt
    }
}

// задаю через docker-compose, поменять на .env файл и изменить сам адрес бд
// const DB_URL: &'static str = env!("DATABASE_URL");
const DB_URL: &str = "postgres://postgres:postgres@db:5432/postgres";

const OK_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
const NOT_FOUND_RESPONSE: &str = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
const INTERNAL_SERVER_ERROR: &str = "HTTP/1.1 500 INTERNAL SERVER ERROR\r\n\r\n";

// изменить структуру до готовой и добавить создание суперюзеров
fn set_database() -> Result<(), PostgresError> {
    let mut client = Client::connect(DB_URL, NoTls)?;

    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR NOT NULL,
            pswd VARCHAR NOT NULL,
            email VARCHAR NOT NULL,
            role  VARCHAR NOT NULL
        )",
    )?;
    Ok(())
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
                r if r.starts_with("POST /sign_up") => handle_sign_up_request(r),
                r if r.starts_with("POST /sign_in") => handle_sign_in_request(r),
                r if r.starts_with("PUT /users/") => handle_put_request(r),
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

fn get_id_from_request(request: &str) -> &str {
    request
        .split("/")
        .nth(2)
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or_default()
}

fn get_token_from_request(request: &str) -> Result<&str, std::io::Error> {
    let token: &str = &request.clone().split("\r\n").nth(1).unwrap_or_default()[22..];
    Ok(token)
}

fn get_user_request_body(request: &str) -> Result<User, serde_json::Error> {
    serde_json::from_str(request.split("\r\n\r\n").last().unwrap_or_default())
}

// добавить создание новых токенов
fn handle_put_request(request: &str) -> (String, String) {
    match (
        get_user_request_body(&request),
        get_token_from_request(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(user), Ok(token), Ok(mut client)) => {
            match Claims::verify_token(token, &user) {
                Ok(claims) => match claims.role {
                    r if r == "user".to_string() => {
                        match (
                            client.query_one(
                            "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                            &[&user.email]),
                            client.query_one("SELECT users.id FROM users WHERE users.email = $1", &[&claims.aud]),
                        ) {
                            (Ok(check_email), Ok(id)) => {

                                let user_presence: bool = check_email.get(0);
                                let actual_id: i32 = id.get(0); 
                                    
                                    // изменённый email и истинный email
                                if user.email != Some(claims.aud) {
                                    if user_presence == false {
                                        let mut db = PasswordForDatabase {
                                            pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                                            db_salt_component: [
                                                // This value was generated from a secure PRNG.
                                                0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                                                0xfe, 0x39, 0x01, 0x8a,
                                            ],
                                        };
                                            
                                        let hash_pswd = db.generate_hash_password(&user);

                                        client
                                            .execute(
                                            "UPDATE users SET (name, pswd, email, role) VALUES ($1, $2, $3, $4) WHERE id = $5",
                                            &[&user.name, &hash_pswd, &user.email, &"user".to_string(), &actual_id],
                                        )
                                        .unwrap();

                                        (OK_RESPONSE.to_string(), "User updated".to_string())
                                    } else {
                                        (
                                            OK_RESPONSE.to_string(), // изменить на другу ошибку
                                            "This email is already taken".to_string(),
                                        )
                                    }
                                } else {
                                    let mut db = PasswordForDatabase {
                                        pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                                        db_salt_component: [
                                            // This value was generated from a secure PRNG.
                                            0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                                            0xfe, 0x39, 0x01, 0x8a,
                                        ],
                                    };

                                    let hash_pswd = db.generate_hash_password(&user);

                                    println!("User_name: {:?}, pswd: {}, user_email: {:?}, id: {}", &user.name, &hash_pswd, &user.email, &actual_id);

                                    client
                                        .execute(
                                        "UPDATE users SET (name, pswd, email, role) = ($1, $2, $3, $4) WHERE id = $5",
                                        &[&user.name, &hash_pswd, &user.email, &"user".to_string(), &actual_id],
                                    )
                                    .unwrap();

                                    (OK_RESPONSE.to_string(), "User updated".to_string())
                                }
                            }
                            _ => {
                                (
                                    OK_RESPONSE.to_string(), // изменить на другу ошибку
                                    "Error creating initial table or there is no user with this id".to_string(),
                                )
                            }
                        }
                    }
                    r if r == "admin".to_string() => {
                        match get_id_from_request(&request).parse::<i32>() {
                            Ok(get_id) => {
                                if get_id == 0 {
                                    match (
                                    client.query_one(
                                    "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                                    &[&user.email]),
                                    client.query_one("SELECT users.id FROM users WHERE users.email = $1", &[&claims.aud]),
                                ) {
                                        (Ok(check_email), Ok(id)) => {
                                            let user_presence: bool = check_email.get(0);
                                            let actual_id: i32 = id.get(0); 
        
                                            // изменённый email и истинный email
                                            if user.email != Some(claims.aud) {
                                                if user_presence == false {
                                                    let mut db = PasswordForDatabase {
                                                        pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                                                        db_salt_component: [
                                                            // This value was generated from a secure PRNG.
                                                            0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                                                            0xfe, 0x39, 0x01, 0x8a,
                                                        ],
                                                    };
                                                    
                                                    let hash_pswd = db.generate_hash_password(&user);
        
                                                    client
                                                        .execute(
                                                        "UPDATE users SET (name, pswd, email, role) VALUES ($1, $2, $3, $4) WHERE id = $5",
                                                        &[&user.name, &hash_pswd, &user.email, &"user".to_string(), &actual_id],
                                                    )
                                                    .unwrap();
        
                                                    (OK_RESPONSE.to_string(), "User updated".to_string())
                                                } else {
                                                    (
                                                        OK_RESPONSE.to_string(), // изменить на другу ошибку
                                                        "This email is already taken".to_string(),
                                                    )
                                                }
                                            } else {
                                                let mut db = PasswordForDatabase {
                                                    pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                                                    db_salt_component: [
                                                        // This value was generated from a secure PRNG.
                                                        0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                                                        0xfe, 0x39, 0x01, 0x8a,
                                                    ],
                                                };
        
                                                let hash_pswd = db.generate_hash_password(&user);
        
                                                client
                                                    .execute(
                                                    "UPDATE users SET (name, pswd, email, role) VALUES ($1, $2, $3, $4) WHERE id = $5",
                                                    &[&user.name, &hash_pswd, &user.email, &"user".to_string(), &actual_id],
                                                )
                                                .unwrap();
        
                                                (OK_RESPONSE.to_string(), "User updated".to_string())
                                            }
                                        }
                                        _ => {
                                            (
                                                OK_RESPONSE.to_string(), // изменить на другу ошибку
                                                "Error creating initial table".to_string(),
                                            )
                                        }
                                    }
                                } else {
                                    match client.query_one(
                                        "SELECT EXISTS(SELECT users.id FROM users WHERE users.id = $1)",
                                        &[&get_id]) {
                                        Ok(check_id) => {
                                            let user_id_presence: bool = check_id.get(0);
                                            if user_id_presence == true {
                                                let mut db = PasswordForDatabase {
                                                    pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                                                    db_salt_component: [
                                                        // This value was generated from a secure PRNG.
                                                        0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                                                        0xfe, 0x39, 0x01, 0x8a,
                                                    ],
                                                };
                                                
                                                let hash_pswd = db.generate_hash_password(&user);
    
                                                client
                                                    .execute(
                                                    "UPDATE users SET (name, pswd, email, role) VALUES ($1, $2, $3, $4) WHERE id = $5",
                                                    &[&user.name, &hash_pswd, &user.email, &"user".to_string(), &get_id],
                                                )
                                                .unwrap();
    
                                                (OK_RESPONSE.to_string(), "User updated".to_string())

                                            } else {
                                                (
                                                    OK_RESPONSE.to_string(), // изменить на другу ошибку
                                                    "There is no user with this id".to_string(),
                                                )
                                            }
                                        }
                                        _ => {
                                            (
                                                OK_RESPONSE.to_string(), // изменить на другу ошибку
                                                "Error creating initial table".to_string(),
                                            )
                                        }
                                    }
                                }
                            }
                            _ => {
                                (
                                    OK_RESPONSE.to_string(), // изменить на другу ошибку
                                    "Some problem with request".to_string(),
                                )
                            }
                        }
                    }
                    _ => {
                        (
                            OK_RESPONSE.to_string(), // изменить на другу ошибку
                            "This role has no privileges".to_string(),
                        )
                    }
                },
                _ => {
                    (
                        OK_RESPONSE.to_string(), // изменить на другу ошибку
                        "Token is invalid".to_string(),
                    )
                }
            }

            /*
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
                        let hash_pswd = db.generate_hash_password(&user);

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
            */
        }
        _ => {
            // println!("Request: {}", request.clone());
            // println!("---------------");
            // let id = request
            //     .clone()
            //     .split("/")
            //     .nth(2)
            //     .unwrap_or_default()
            //     .split_whitespace()
            //     .next()
            //     .unwrap_or_default();
            // println!("Id: {}", id);
            // println!("Request: {}", request.clone());
            // println!("---------------");
            // let user_info: serde_json::Value =
            //     serde_json::from_str(request.clone().split("\r\n\r\n").last().unwrap_or_default())
            //         .unwrap();
            // println!("User info: {:?}", user_info);
            (
                INTERNAL_SERVER_ERROR.to_string(),
                "Internal Error".to_string(),
            )
        }
    }
}

fn handle_sign_up_request(request: &str) -> (String, String) {
    match (
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(user), Ok(mut client)) => {
            // println!("{:#?}", user);
            // panic!();

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
                        let hash_pswd = db.generate_hash_password(&user);

                        client
                            .execute(
                                "INSERT INTO users (name, pswd, email, role) VALUES ($1, $2, $3, $4)",
                                &[&user.name, &hash_pswd, &user.email, &"user".to_string()],
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
        _ => (
            INTERNAL_SERVER_ERROR.to_string(),
            "Internal Error".to_string(),
        ),
    }
}

fn handle_sign_in_request(request: &str) -> (String, String) {
    match (
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(mut user), Ok(mut client)) => {
            user.role = Some("user".to_string());
            match client.query_one(
                "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                &[&user.email],
            ) {
                Ok(row) => {
                    let db = PasswordForDatabase {
                        pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
                        db_salt_component: [
                            // Нужно задать новый db_salt_component и вынести за запросы                     !!!!
                            // This value was generated from a secure PRNG.
                            0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                            0xfe, 0x39, 0x01, 0x8a,
                        ],
                    };

                    let user_email_presence: bool = row.get(0);
                    if user_email_presence == true {
                        let verification = db.verify_password(&user, &mut client);

                        if verification == true {
                            // create jws token
                            let token = Claims::create_jwt_token(&user); // нужно ли делать проверку, создался ли токен?

                            // let role = Claims::verify_token(&token, &user);

                            // (
                            //     OK_RESPONSE.to_string(),
                            //     "Token :".to_string() + token.as_str(),
                            // )
                            (
                                OK_RESPONSE.to_string(),
                                "Token: ".to_string() + token.as_str(),
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
