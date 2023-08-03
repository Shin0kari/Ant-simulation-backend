use ring::{digest, pbkdf2};

use std::num::NonZeroU32;

use data_encoding::HEXUPPER;
use postgres::Error as PostgresError;
use postgres::{Client, NoTls};
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use time::{Duration, OffsetDateTime};

use serde::{Deserialize, Serialize};

// поменять секретный ключ на что то более секретное
const KEY: &str = "secret";

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

// задаю через docker-compose, поменять на .env файл и изменить сам адрес бд
const DB_URL: &'static str = env!("DATABASE_URL");
// const DB_URL: &str = "postgres://postgres:postgres@db:5432/postgres";

const OK_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
const NOT_FOUND_RESPONSE: &str = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
const INTERNAL_SERVER_ERROR: &str = "HTTP/1.1 500 INTERNAL SERVER ERROR\r\n\r\n";

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

#[derive(Serialize, Deserialize)]
struct User {
    id: Option<i32>,
    role: Option<String>,
    name: Option<String>,
    pswd: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // email
    // aud: String, // email, было изменил
    #[serde(with = "jwt_numeric_date")]
    iat: OffsetDateTime,
    #[serde(with = "jwt_numeric_date")]
    exp: OffsetDateTime,
    pswd: String, // мб это убрать, нужо будет спросить
    role: String,
}

impl Claims {
    // Проверка JWT
    pub fn verify_token(token: &str, _user: &User) -> Result<Claims, std::io::Error> {
        let decoding_key = DecodingKey::from_secret(KEY.as_bytes());
        let validation = Validation::new(Algorithm::HS512);

        let token_data = match decode::<Claims>(&token, &decoding_key, &validation) {
            Ok(c) => c,
            Err(err) => match *err.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => panic!("Token is invalid"), // Example on how to handle a specific error
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => panic!("Issuer is invalid"), // Example on how to handle a specific error
                _ => panic!("Some other errors"),
            },
        };

        Ok(token_data.claims)
    }

    // если меняется одно из aud(email), pswd, role то создаём заново токен для пользователя
    pub fn create_jwt_token(user: &User) -> String {
        let my_claims = Claims {
            sub: user.email.clone().unwrap().to_owned(),
            // aud: user.email.clone().unwrap().to_owned(),
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

struct PasswordForDatabase {
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
                0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1,
                0xfe, 0x39, 0x01, 0x8a,
            ],
        };

        let salt = db.salt(&user.email.as_ref().unwrap());
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
        // добавить проверку подключения к бд
        match client.query_one(
            "SELECT users.pswd FROM users WHERE users.email = $1",
            &[&user.email],
        ) {
            Ok(row) => {
                let actual_pswd: String = row.get(0);
                let hash_pswd = PasswordForDatabase::generate_hash_password(&user);

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

// изменить структуру до готовой и добавить создание суперюзеров?
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

fn user_update(user: User, mut client: Client, actual_id: i32) -> (String, String) {
    let hash_pswd = PasswordForDatabase::generate_hash_password(&user);

    client
        .execute(
        "UPDATE users SET (name, pswd, email) = ($1, $2, $3) WHERE id = $4",
        &[&user.name, &hash_pswd, &user.email, &actual_id],
    )
    .unwrap();

    (OK_RESPONSE.to_string(), "User updated".to_string())
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
                Ok(claims) => {
                    match claims.role {
                    r if r == "user".to_string() => {
                        println!("Ne admin");
                        match (
                            client.query_one(
                            "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                            &[&user.email]),
                            client.query_one("SELECT users.id FROM users WHERE users.email = $1", &[&claims.sub]),
                        ) {
                            (Ok(check_email), Ok(id)) => {
                                let user_email_presence: bool = check_email.get(0);
                                let actual_id: i32 = id.get(0); 
 
                                if user.email != Some(claims.sub) {
                                    if user_email_presence == false {
                                        user_update(user, client, actual_id)
                                    } else {
                                        (
                                            OK_RESPONSE.to_string(), // изменить на другу ошибку
                                            "This email is already taken".to_string(),
                                        )
                                    }
                                } else {
                                    user_update(user, client, actual_id)
                                }
                            }
                            _ => {
                                (
                                    OK_RESPONSE.to_string(), // изменить на другу ошибку
                                    "Error creating initial table or there is no user with this id".to_string(),
                                )
                            }
                        }
                    },
                    r if r == "admin".to_string() => {
                        match get_id_from_request(&request).parse::<i32>() {
                            Ok(get_id) => {
                                // изменяет кого-то
                                match client.query_one("SELECT EXISTS(SELECT users.id FROM users WHERE users.id = $1)",
                                    &[&get_id]) {
                                    Ok(check_id) => {  
                                        let user_id_presence: bool = check_id.get(0);

                                        if user_id_presence {
                                            // 1-ое для проверки, чтобы не поменяли на тот же email, 2-ое для получения email пользователя
                                            match (client.query_one("SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)", 
                                                &[&user.email]), 
                                                client.query_one("SELECT users.email FROM users WHERE users.id = $1", &[&get_id]),
                                            ) {
                                                (Ok(check_email), Ok(get_email)) => {
                                                    let user_email_presence: bool = check_email.get(0);
                                                    let get_user_email: String = get_email.get(0);

                                                    match (user_email_presence, get_user_email) {
                                                        (presence_email, actual_email) if presence_email && actual_email == user.email.clone().unwrap() => {
                                                            user_update(user, client, get_id)
                                                        }
                                                        (presence_email, actual_email) if presence_email == false => {
                                                            user_update(user, client, get_id)
                                                        }
                                                        _ => {
                                                            (
                                                                OK_RESPONSE.to_string(), // изменить на другу ошибку
                                                                "This email is already taken".to_string(),
                                                            )
                                                        }
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
                            _ => {
                                // вроде хватит только выбора id т.к. это проверяет наличие пользователя
                                // изменяем себя
                                match (
                                    client.query_one("SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)", 
                                    &[&user.email]), 
                                    client.query_one("SELECT users.id FROM users WHERE users.email = $1", 
                                    &[&claims.sub]),) {
                                    (Ok(check_email), Ok(get_id)) => {
                                        let user_email_presence: bool = check_email.get(0);
                                        let actual_id: i32 = get_id.get(0); 
                                                // изменённый email и истинный email
                                        if user.email != Some(claims.sub) {
                                            if user_email_presence == false {
                                                user_update(user, client, actual_id)
                                            } else {
                                                (
                                                    OK_RESPONSE.to_string(), // изменить OK_RESPONSE на другу ошибку
                                                    "This email is already taken".to_string(),
                                                )
                                            }
                                        } else {
                                            user_update(user, client, actual_id)
                                        }
                                    }
                                    _ => {
                                        (
                                            OK_RESPONSE.to_string(), // изменить OK_RESPONSE на другу ошибку
                                            "Error creating initial table".to_string(),
                                        )
                                    }
                                }
                            }
                        }
                    },
                    _ => {
                        (
                            OK_RESPONSE.to_string(), // изменить на другу ошибку
                            "This role has no privileges".to_string(),
                        )
                    }
                }
            }
                _ => {
                    (
                        OK_RESPONSE.to_string(), // изменить на другу ошибку
                        "Token is invalid".to_string(),
                    )
                }
            }
        }
        _ => {
            (
                INTERNAL_SERVER_ERROR.to_string(),
                "Internal Error".to_string(),
            )
        }
    }
}

// добавить валидацию email и name
fn handle_sign_up_request(request: &str) -> (String, String) {
    match (
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(user), Ok(mut client)) => {
            match (
                client.query_one(
                "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                &[&user.email],),
                client.query_one(
                "SELECT EXISTS(SELECT users.name FROM users WHERE users.email = $1)",
                &[&user.email],)
            ) {
                (Ok(check_email), Ok(check_name)) => {
                    let user_email_presence: bool = check_email.get(0);
                    let user_name_presence: bool = check_name.get(0);

                    match (user_email_presence, user_name_presence) {
                        (email_presence, name_presence) if email_presence == false && name_presence == false => {
                            let hash_pswd = PasswordForDatabase::generate_hash_password(&user);

                            client
                                .execute(
                                    "INSERT INTO users (name, pswd, email, role) VALUES ($1, $2, $3, $4)",
                                    &[&user.name, &hash_pswd, &user.email, &"user".to_string()],
                                )
                                .unwrap();

                            (OK_RESPONSE.to_string(), "User registered".to_string())
                        },
                        (email_presence, name_presence) if email_presence == false && name_presence => {
                            (
                                OK_RESPONSE.to_string(),
                                "This name is already taken".to_string(),
                            )
                        },
                        (email_presence, name_presence) if email_presence && name_presence == false => {
                            (
                                OK_RESPONSE.to_string(),
                                "This email is already taken".to_string(),
                            )
                        },
                        _ => {
                            (
                                OK_RESPONSE.to_string(),
                                "This email and name is already taken".to_string(),
                            )
                        }                        
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
            match client.query_one(
                "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                &[&user.email],
                
            ) {
                Ok(email_presence) => {
                    let user_email_presence: bool = email_presence.get(0);

                    if user_email_presence {
                        match client.query_one("SELECT users.role FROM users WHERE users.email = $1", &[&user.email]) {
                            Ok(user_role) => {
                                user.role = Some(user_role.get(0));
                                
                                let verification_complete = PasswordForDatabase::verify_password(&user, &mut client);
    
                                if verification_complete {
                                    let token = Claims::create_jwt_token(&user); // нужно ли делать проверку, создался ли токен?
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
                            }
                            _ => {(
                                OK_RESPONSE.to_string(), // изменить на другу ошибку
                                "Trouble getting role".to_string(),
                            )}
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
