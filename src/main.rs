use ring::{digest, pbkdf2};
use serde_json::{json, Value};

use std::num::NonZeroU32;

// у меня проект в паке rs_crud, хоть в гите и по другому
use ::rs_crud::data::sql_scripts::{
    CREATE_DIAG, DELETE_FRIEND_LIST_SCRIPT, DELETE_FRIEND_SCRIPT, DELETE_USER_ACH_SCRIPT,
    DELETE_USER_FROM_FRIEND_LISTS_SCRIPT, DELETE_USER_INFO_SCRIPT, DELETE_USER_SCRIPT,
    INSERT_ACH_USER_SCRIPT, INSERT_FRIEND_LIST_SCRIPT, INSERT_USER_INFO_SCRIPT, INSERT_USER_SCRIPT,
    SELECT_FRIEND_LIST_SCRIPT, SELECT_NICKNAME_SCRIPT, SELECT_ROLE_SCRIPT, SELECT_USER_ACH_SCRIPT,
    SELECT_USER_INFO_SCRIPT, SELECT_USER_SCRIPT, UPDATE_ACH_USER_SCRIPT, UPDATE_USER_INFO_SCRIPT,
    UPDATE_USER_SCRIPT,
};

use data_encoding::HEXUPPER;
use postgres::Error as PostgresError;
use postgres::{Client, NoTls};
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use time::{Duration, OffsetDateTime};

use serde::{Deserialize, Serialize};

use validator::Validate;

// не менять секретный ключ на что то более секретное
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

    /// Attempts to deserialize an i32 and use as a Unix timestamp
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }
}

#[derive(Serialize, Deserialize, Debug, Validate, Clone)]
struct User {
    id: Option<i32>,
    #[validate(required, length(min = 4))]
    pswd: Option<String>,
    #[validate(email)]
    email: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Validate, Clone)]
struct UserInfo {
    role: Option<String>,
    #[validate(required, length(min = 1))]
    name: Option<String>,
    training_complete: Option<bool>,
    mtx_lvl: Option<i16>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserAch {
    ach: Option<Vec<bool>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserListFriend {
    frined_list: Option<Vec<i32>>,
    friend_id: Option<i32>,
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
    pub fn verify_token(token: &str) -> Result<Claims, (String, serde_json::Value)> {
        let decoding_key = DecodingKey::from_secret(KEY.as_bytes());
        let validation = Validation::new(Algorithm::HS512);

        match decode::<Claims>(&token, &decoding_key, &validation) {
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
                0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1, 0xfe, 0x39,
                0x01, 0x8a,
            ],
        };

        let salt = db.salt(&user.email.as_ref().unwrap());
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

fn set_database() -> Result<(), PostgresError> {
    let mut client = Client::connect(DB_URL, NoTls)?;

    client.batch_execute(CREATE_DIAG)?;
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

fn get_user_request_body(
    request: &str,
) -> Result<(User, UserInfo, UserAch, UserListFriend), (String, Value)> {
    match serde_json::from_str(request.split("\r\n\r\n").last().unwrap_or_default()) {
        Ok(val) => {
            let data_value: Value = val;
            let user = User {
                id: Some(
                    data_value["user"]["id"]
                        .as_i64()
                        .unwrap_or_default()
                        .to_string()
                        .parse::<i32>()
                        .unwrap_or_default(),
                ),
                pswd: Some(
                    data_value["user"]["pswd"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                ),
                email: Some(
                    data_value["user"]["email"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                ),
            };

            let user_info = UserInfo {
                role: None,
                name: Some(
                    data_value["user_info"]["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                ),
                training_complete: Some(
                    data_value["user_info"]["training_complete"]
                        .as_bool()
                        .unwrap_or_default(),
                ),
                mtx_lvl: None,
            };

            let mut request_ach: Vec<bool> = Vec::new();

            if data_value["user_ach"].clone().is_null() == false {
                for i in 0..data_value["user_ach"]
                    .clone()
                    .as_array()
                    .expect("Somthink wrong with ach, the programmer will cry")
                    .len()
                {
                    request_ach.push(data_value["user_ach"][i].as_bool().unwrap_or_default());
                }
            }

            let user_ach = UserAch {
                ach: Some(request_ach),
            };

            let friend_list = UserListFriend {
                frined_list: None,
                friend_id: Some(
                    data_value["friend_id"]
                        .as_i64()
                        .unwrap_or_default()
                        .to_string()
                        .parse::<i32>()
                        .unwrap_or_default(),
                ),
            };

            println!(
                "Len in request body: {:?}",
                user.pswd.clone().unwrap_or_default().len()
            );

            Ok((user, user_info, user_ach, friend_list))
        }
        _ => {
            let response: serde_json::Value =
                json!({ "Error": "error occurred while processing the request" });
            Err((OK_RESPONSE.to_string(), response))
        }
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

            let (status_line, content) = match request.as_str() {
                r if r.starts_with("POST /sign_up") => handle_sign_up_request(r),
                r if r.starts_with("POST /sign_in") => handle_sign_in_request(r),
                r if r.starts_with("PUT /user/") => handle_put_request(r),
                r if r.starts_with("POST /user_friend/") => handle_add_friend_request(r),
                r if r.starts_with("DELETE /user_friend/") => handle_delete_friend_request(r),
                r if r.starts_with("GET /user/") => handle_get_request(r),
                r if r.starts_with("DELETE /delete_user/") => handle_delete_request(r),
                _ => {
                    let response: serde_json::Value = json!({ "Error": "Not found response" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
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

fn update_user(
    user: &mut User,
    user_info: &mut UserInfo,
    user_ach: UserAch,
    client: &mut Client,
    actual_id: i32,
) -> (String, serde_json::Value) {
    match select_user_data(actual_id, client) {
        Ok((db_user, db_user_info, db_user_ach, _db_user_friends)) => {
            let hash_pswd = PasswordForDatabase::generate_hash_password(&user);

            // let mut check_user_email = user.email.clone().is_none();
            // let mut check_user_pswd = user.pswd.clone().is_none();
            // let mut check_user_info_name = user_info.name.clone().is_none();
            let check_user_info_role = user_info.role.clone().is_none();
            let check_user_info_mtx_lvl = user_info.mtx_lvl.clone().is_none();
            let check_user_info_training_complete = user_info.training_complete.clone().is_none();

            if user.email.clone().unwrap_or_default().len() == 0 {
                user.email = db_user.email;
            }
            if user.pswd.clone().unwrap_or_default().len() == 0 {
                user.pswd = db_user.pswd;
            }
            if user_info.name.clone().unwrap_or_default().len() == 0 {
                user_info.name = db_user_info.name;
            }
            if check_user_info_role {
                user_info.role = db_user_info.role;
            }
            if check_user_info_mtx_lvl {
                user_info.mtx_lvl = db_user_info.mtx_lvl;
            }
            if check_user_info_training_complete {
                user_info.training_complete = db_user_info.training_complete;
            }

            match (
                client.execute(UPDATE_USER_SCRIPT, &[&actual_id, &hash_pswd, &user.email]),
                client.execute(
                    UPDATE_USER_INFO_SCRIPT,
                    &[&actual_id, &user_info.name, &user_info.training_complete],
                ),
            ) {
                (Ok(_check_update_user), Ok(_check_update_user_info)) => {
                    // необходим при обновлении email и pswd пользователя
                    let token = Claims::create_jwt_token(&user, &user_info);

                    // // для user_ach
                    let mut data_ach: Vec<bool> = Vec::new();
                    let mut update_user_ach = user_ach.ach.clone().unwrap_or_default().into_iter();

                    for actual_user_ach in db_user_ach.ach.unwrap_or_default() {
                        if (actual_user_ach || update_user_ach.next().unwrap_or_default()) == true {
                            data_ach.push(true);
                        } else {
                            data_ach.push(false);
                        }
                    }

                    client
                        .execute(
                            UPDATE_ACH_USER_SCRIPT,
                            &[
                                &actual_id,
                                &data_ach[0],
                                &data_ach[1],
                                &data_ach[2],
                                &data_ach[3],
                                &data_ach[4],
                            ],
                        )
                        .unwrap();

                    let response: serde_json::Value = json!({ "Response": token });
                    (OK_RESPONSE.to_string(), response)
                }
                _ => {
                    let response: serde_json::Value =
                        json!({ "Error": "Error occurred while updating the user" });
                    (OK_RESPONSE.to_string(), response)
                }
            }
        }
        _ => {
            let response: serde_json::Value = json!({ "Error": "An error occurred while retrieving user data when updating user info" });
            (OK_RESPONSE.to_string(), response)
        }
    }
}

fn select_user_data(
    actual_id: i32,
    client: &mut Client,
) -> Result<(User, UserInfo, UserAch, UserListFriend), (String, serde_json::Value)> {
    match (
        get_user(actual_id, client),
        get_user_info(actual_id, client),
        get_user_ach(actual_id, client),
        get_user_friends(actual_id, client),
    ) {
        (Ok(user), Ok(user_info), Ok(user_ach), Ok(friend_list)) => {
            Ok((user, user_info, user_ach, friend_list))
        }
        _ => {
            let response: serde_json::Value = json!({ "Error": "Error creating initial table" });
            Err((OK_RESPONSE.to_string(), response))
        }
    }
}

fn get_user_friends(actual_id: i32, client: &mut Client) -> Result<UserListFriend, PostgresError> {
    match client.query(SELECT_FRIEND_LIST_SCRIPT, &[&actual_id]) {
        Ok(db_data) => {
            let mut data_id_friends: Vec<i32> = Vec::new();

            for id in db_data {
                data_id_friends.push(id.get(0));
            }

            Ok(UserListFriend {
                frined_list: Some(data_id_friends),
                friend_id: None,
            })
        }
        Err(error) => Err(error),
    }
}

fn get_user_ach(actual_id: i32, client: &mut Client) -> Result<UserAch, PostgresError> {
    match client.query_one(SELECT_USER_ACH_SCRIPT, &[&actual_id]) {
        Ok(db_data) => {
            let mut data_ach: Vec<bool> = Vec::new();

            for i in 0..db_data.len() {
                data_ach.push(db_data.get(i));
            }

            Ok(UserAch {
                ach: Some(data_ach),
            })
        }
        Err(error) => Err(error),
    }
}

fn get_user(actual_id: i32, client: &mut Client) -> Result<User, PostgresError> {
    match client.query_one(SELECT_USER_SCRIPT, &[&actual_id]) {
        Ok(db_data) => Ok(User {
            id: Some(db_data.get(0)),
            pswd: Some(db_data.get(1)),
            email: Some(db_data.get(2)),
        }),
        Err(error) => Err(error),
    }
}

fn get_user_info(actual_id: i32, client: &mut Client) -> Result<UserInfo, PostgresError> {
    match client.query_one(SELECT_USER_INFO_SCRIPT, &[&actual_id]) {
        Ok(db_data) => Ok(UserInfo {
            name: Some(db_data.get(0)),
            role: Some(db_data.get(1)),
            training_complete: Some(db_data.get(2)),
            mtx_lvl: Some(db_data.get(3)),
        }),
        Err(error) => Err(error),
    }
}

fn read_user(mut client: Client, actual_id: i32) -> (String, serde_json::Value) {
    match select_user_data(actual_id, &mut client) {
        Ok((user, user_info, user_ach, friend_list)) => {
            let mut ach_str = "".to_string();
            // no unwrap?
            for ach in user_ach.ach.unwrap().iter() {
                if *ach {
                    ach_str = ach_str + "true "
                } else {
                    ach_str = ach_str + "false "
                }
            }

            let mut friends_id_str = "".to_string();
            for id in friend_list.frined_list.unwrap() {
                friends_id_str = friends_id_str + id.to_string().as_str() + " ";
            }

            let response: serde_json::Value = json!({
                "Response": {
                    "User": {
                        "id": user.id.unwrap(),
                        "email": user.email.unwrap()
                    },
                    "User_info": {
                        "name": user_info.name.unwrap(),
                        "role": user_info.role.unwrap(),
                        "training_complete": user_info.training_complete.unwrap(),
                        "mtx_lvl": user_info.mtx_lvl.unwrap()
                    },
                    "User_ach": {
                        "ach": ach_str,
                    },
                    "Friend_list": {
                        "friends_id": friends_id_str,
                    }
                }
            });
            (OK_RESPONSE.to_string(), response)
        }
        _ => {
            let response: serde_json::Value = json!({ "Error": "Error creating initial table" });
            (OK_RESPONSE.to_string(), response)
        }
    }
}

fn handle_get_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_token_from_request(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(token), Ok(mut client)) => match Claims::verify_token(token) {
            Ok(claims) => match claims.role {
                r if r == "user".to_string() => {
                    match client.query_one(
                        "SELECT users.id_user FROM users WHERE users.email = $1",
                        &[&claims.sub],
                    ) {
                        Ok(id) => {
                            let actual_id: i32 = id.get(0);
                            read_user(client, actual_id)
                        }
                        _ => {
                            let response: serde_json::Value = json!({ "Error": "Error creating initial table or there is no user with this email" });
                            (OK_RESPONSE.to_string(), response)
                        }
                    }
                }
                r if r == "admin".to_string() => {
                    match get_id_from_request(&request).parse::<i32>() {
                        Ok(get_id) => read_user(client, get_id),
                        _ => {
                            match client.query_one(
                                "SELECT users.id_user FROM users WHERE users.email = $1",
                                &[&claims.sub],
                            ) {
                                Ok(get_id) => {
                                    let actual_id: i32 = get_id.get(0);
                                    read_user(client, actual_id)
                                }
                                _ => {
                                    let response: serde_json::Value =
                                        json!({ "Error": "Error creating initial table" });
                                    (NOT_FOUND_RESPONSE.to_string(), response)
                                }
                            }
                        }
                    }
                }
                _ => {
                    let response: serde_json::Value =
                        json!({ "Error": "This role has no privileges" });
                    (OK_RESPONSE.to_string(), response)
                }
            },
            _ => {
                let response: serde_json::Value = json!({ "Error": "Token is invalid" });
                (OK_RESPONSE.to_string(), response)
            }
        },
        _ => {
            let response: serde_json::Value = json!({ "Error": "Internal server error" });
            (INTERNAL_SERVER_ERROR.to_string(), response)
        }
    }
}

fn delete_user(mut client: Client, actual_id: i32) -> (String, serde_json::Value) {
    match (
        client.execute(DELETE_USER_INFO_SCRIPT, &[&actual_id]),
        client.execute(DELETE_FRIEND_LIST_SCRIPT, &[&actual_id]),
        client.execute(DELETE_USER_ACH_SCRIPT, &[&actual_id]),
        client.execute(DELETE_USER_SCRIPT, &[&actual_id]),
        client.execute(DELETE_USER_FROM_FRIEND_LISTS_SCRIPT, &[&actual_id]),
    ) {
        (
            Ok(_delete_user_info_line),
            Ok(_delete_friend_list_line),
            Ok(_delete_user_ach_line),
            Ok(_delete_user_line),
            Ok(_delete_user_from_friend_lists_line),
        ) => {
            let response: serde_json::Value = json!({ "Response": "User deleted" });
            (OK_RESPONSE.to_string(), response)
        }
        _ => {
            let response: serde_json::Value = json!({ "Error": "Error initial one of struct" });
            (OK_RESPONSE.to_string(), response)
        }
    }
}

fn handle_delete_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_token_from_request(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(token), Ok(mut client)) => match Claims::verify_token(token) {
            Ok(claims) => match claims.role {
                r if r == "user".to_string() => {
                    match client.query_one(
                        "SELECT users.id_user FROM users WHERE users.email = $1",
                        &[&claims.sub],
                    ) {
                        Ok(id) => {
                            let actual_id: i32 = id.get(0);
                            delete_user(client, actual_id)
                        }
                        _ => {
                            let response: serde_json::Value = json!({ "Error": "Error creating initial table or there is no user with this email" });
                            (OK_RESPONSE.to_string(), response)
                        }
                    }
                }
                r if r == "admin".to_string() => {
                    match get_id_from_request(&request).parse::<i32>() {
                        Ok(get_id) => delete_user(client, get_id),
                        _ => {
                            match client.query_one(
                                "SELECT users.id_user FROM users WHERE users.email = $1",
                                &[&claims.sub],
                            ) {
                                Ok(get_id) => {
                                    let actual_id: i32 = get_id.get(0);
                                    delete_user(client, actual_id)
                                }
                                _ => {
                                    let response: serde_json::Value =
                                        json!({ "Error": "Error creating initial table" });
                                    (OK_RESPONSE.to_string(), response)
                                }
                            }
                        }
                    }
                }
                _ => {
                    let response: serde_json::Value =
                        json!({ "Error": "This role has no privileges" });
                    (OK_RESPONSE.to_string(), response)
                }
            },
            _ => {
                let response: serde_json::Value = json!({ "Error": "Token is invalid" });
                (OK_RESPONSE.to_string(), response)
            }
        },
        _ => {
            let response: serde_json::Value = json!({ "Error": "Internal server error" });
            (INTERNAL_SERVER_ERROR.to_string(), response)
        }
    }
}

// добавить создание новых токенов
fn handle_put_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(&request),
        get_token_from_request(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((mut user, mut user_info, user_ach, _friend_list)), Ok(token), Ok(mut client)) => {
            match (
                Claims::verify_token(token),
                user.clone().validate(),
                user_info.clone().validate(),
            ) {
                (Ok(claims), Ok(_), Ok(_)) => {
                    // возможно изменить на получение роли из бд
                    match claims.role {
                        r if r == "user".to_string() => {
                            user_info.role = Some(r);
                            match (
                                client.query_one(
                                "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                                &[&user.email]),
                                client.query_one("SELECT users.id_user FROM users WHERE users.email = $1", &[&claims.sub]),
                            ) {
                                (Ok(check_email), Ok(id)) => {
                                    let user_email_presence: bool = check_email.get(0);
                                    let actual_id: i32 = id.get(0);

                                    if user.email != Some(claims.sub) {
                                        if user_email_presence == false {
                                            update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
                                        } else {
                                            let response: serde_json::Value =
                                                json!({ "Error": "This email is already taken" });
                                            (OK_RESPONSE.to_string(), response)
                                        }
                                    } else {
                                        update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
                                    }
                                }
                                _ => {
                                    let response: serde_json::Value =
                                        json!({ "Error": "Error creating initial table or there is no user with this id" });
                                    (OK_RESPONSE.to_string(), response)
                                }
                            }
                        }
                        r if r == "admin".to_string() => {
                            user_info.role = Some(r);
                            match get_id_from_request(&request).parse::<i32>() {
                                Ok(get_id) => {
                                    // изменяет кого-то
                                    match client.query_one("SELECT EXISTS(SELECT users.id_user FROM users WHERE users.id_user = $1)",
                                    &[&get_id]) {
                                    Ok(check_id) => {
                                        let user_id_presence: bool = check_id.get(0);

                                        if user_id_presence {
                                            // 1-ое для проверки, чтобы не поменяли на тот же email, 2-ое для получения email пользователя
                                            match (client.query_one("SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                                                &[&user.email]),
                                                client.query_one("SELECT users.email FROM users WHERE users.id_user = $1", &[&get_id]),
                                            ) {
                                                (Ok(check_email), Ok(get_email)) => {
                                                    let user_email_presence: bool = check_email.get(0);
                                                    let get_user_email: String = get_email.get(0);

                                                    match (user_email_presence, get_user_email) {
                                                        (presence_email, actual_email) if presence_email && actual_email == user.email.clone().unwrap() => {
                                                            update_user(&mut user, &mut user_info, user_ach, &mut client, get_id)
                                                        }
                                                        (presence_email, _actual_email) if presence_email == false => {
                                                            update_user(&mut user, &mut user_info, user_ach, &mut client, get_id)
                                                        }
                                                        _ => {
                                                            let response: serde_json::Value =
                                                                json!({ "Error": "This email is already taken" });
                                                            (OK_RESPONSE.to_string(), response)
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    let response: serde_json::Value =
                                                        json!({ "Error": "Error creating initial table" });
                                                    (OK_RESPONSE.to_string(), response)
                                                }
                                            }
                                        } else {
                                            let response: serde_json::Value =
                                                json!({ "Error": "There is no user with this id" });
                                            (OK_RESPONSE.to_string(), response)
                                        }
                                    }
                                    _ => {
                                        let response: serde_json::Value =
                                            json!({ "Error": "Error creating initial table" });
                                        (OK_RESPONSE.to_string(), response)
                                    }
                                }
                                }
                                _ => {
                                    match (
                                    client.query_one("SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                                    &[&user.email]),
                                    client.query_one("SELECT users.id_user FROM users WHERE users.email = $1",
                                    &[&claims.sub]),) {
                                    (Ok(check_email), Ok(get_id)) => {
                                        let user_email_presence: bool = check_email.get(0);
                                        let actual_id: i32 = get_id.get(0);
                                                // изменённый email и истинный email
                                        if user.email != Some(claims.sub) {
                                            if user_email_presence == false {
                                                update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
                                            } else {
                                                let response: serde_json::Value =
                                                    json!({ "Error": "This email is already taken" });
                                                (OK_RESPONSE.to_string(), response)
                                            }
                                        } else {
                                            update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
                                        }
                                    }
                                    _ => {
                                        let response: serde_json::Value =
                                            json!({ "Error": "Error creating initial table" });
                                        (OK_RESPONSE.to_string(), response)
                                    }
                                }
                                }
                            }
                        }
                        _ => {
                            let response: serde_json::Value =
                                json!({ "Error": "This role has no privileges" });
                            (OK_RESPONSE.to_string(), response)
                        }
                    }
                }
                (Ok(_), Err(_), Ok(_)) => {
                    let response: serde_json::Value =
                        json!({ "Error": "This user email is not available" });
                    (OK_RESPONSE.to_string(), response)
                }
                (Ok(_), Ok(_), Err(_)) => {
                    let response: serde_json::Value =
                        json!({ "Error": "This user nickname is not available" });
                    (OK_RESPONSE.to_string(), response)
                }
                _ => {
                    let response: serde_json::Value = json!({ "Error": "Token is invalid" });
                    (OK_RESPONSE.to_string(), response)
                }
            }
        }
        (Err(error), Ok(_), Ok(_)) => error,
        _ => {
            let response: serde_json::Value = json!({ "Error": "Internal server error" });
            (INTERNAL_SERVER_ERROR.to_string(), response)
        }
    }
}

fn handle_delete_friend_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(&request),
        get_token_from_request(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((_user, _user_info, _user_ach, friend_list)), Ok(token), Ok(mut client)) => {
            match Claims::verify_token(token) {
                Ok(claims) => {
                    match client.query_one(
                        "SELECT users.id_user FROM users WHERE users.email = $1",
                        &[&claims.sub],
                    ) {
                        Ok(user_id) => {
                            let actual_id: i32 = user_id.get(0);
                            match client.query_one(
                                "SELECT EXISTS(SELECT friend_list.friend_id FROM friend_list WHERE id_user = $2 AND friend_id = $1)",
                                &[&friend_list.friend_id, &actual_id],
                            ) {
                                Ok(check_if_friend_in_friend_list) => {
                                    let check_friend: bool = check_if_friend_in_friend_list.get(0);
                                    if check_friend {
                                        client
                                            .execute(
                                                DELETE_FRIEND_SCRIPT,
                                                &[&friend_list.friend_id, &actual_id],
                                            )
                                            .unwrap();
                                        let response: serde_json::Value =
                                            json!({ "Response": "User removed from your friends list" });
                                        (OK_RESPONSE.to_string(), response)
                                    } else {
                                        let response: serde_json::Value =
                                            json!({ "Error": "There is no friend with this id in your friends list" });
                                        (OK_RESPONSE.to_string(), response)
                                    }
                                }
                                _ => {
                                    let response: serde_json::Value =
                                        json!({ "Error": "Some problem with connect to database" });
                                    (OK_RESPONSE.to_string(), response)
                                }
                            }
                        }
                        _ => {
                            let response: serde_json::Value =
                                json!({ "Error": "Some problem with connect to database" });
                            (OK_RESPONSE.to_string(), response)
                        }
                    }
                }
                _ => {
                    let response: serde_json::Value = json!({ "Error": "Token is not valid or some problem with connect to database" });
                    (OK_RESPONSE.to_string(), response)
                }
            }
        }
        (Err(error), Ok(_), Ok(_)) => error,
        _ => {
            let response: serde_json::Value = json!({ "Error": "Internal server error" });
            (INTERNAL_SERVER_ERROR.to_string(), response)
        }
    }
}

fn handle_add_friend_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(&request),
        get_token_from_request(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((_user, _user_info, _user_ach, friend_list)), Ok(token), Ok(mut client)) => {
            match (
                Claims::verify_token(token),
                client.query_one(
                    "SELECT EXISTS(SELECT users.id_user FROM users WHERE users.id_user = $1)",
                    &[&friend_list.friend_id],
                ),
            ) {
                (Ok(claims), Ok(check_id)) => {
                    let friend_id_presence: bool = check_id.get(0);

                    if friend_id_presence {
                        match client.query_one(
                            "SELECT users.id_user FROM users WHERE users.email = $1",
                            &[&claims.sub],
                        ) {
                            Ok(user_id) => {
                                let actual_id: i32 = user_id.get(0);
                                match client.query_one(
                                    "SELECT EXISTS(SELECT friend_list.friend_id FROM friend_list WHERE id_user = $2 AND friend_id = $1)",
                                    &[&friend_list.friend_id, &actual_id],
                                ) {
                                    Ok(check_if_friend_in_friend_list) => {
                                        let check_friend: bool = check_if_friend_in_friend_list.get(0);
                                        if check_friend == false && actual_id != friend_list.friend_id.unwrap_or_default() {
                                            client
                                                .execute(
                                                    INSERT_FRIEND_LIST_SCRIPT,
                                                    &[&friend_list.friend_id, &actual_id],
                                                )
                                                .unwrap();
                                            let response: serde_json::Value =
                                                json!({ "Response": "Friend added to friends list" });
                                            (OK_RESPONSE.to_string(), response)
                                        } else if actual_id == friend_list.friend_id.unwrap_or_default() {
                                            let response: serde_json::Value =
                                                json!({ "Error": "You are trying to add your id to your friends list" });
                                            (OK_RESPONSE.to_string(), response)
                                        } else {
                                            let response: serde_json::Value =
                                                json!({ "Error": "Friend has already been added to the friends list" });
                                            (OK_RESPONSE.to_string(), response)
                                        }
                                    }
                                    _ => {
                                        let response: serde_json::Value =
                                            json!({ "Error": "Some problem with connect to database" });
                                        (OK_RESPONSE.to_string(), response)
                                    }
                                }
                            }
                            _ => {
                                let response: serde_json::Value =
                                    json!({ "Error": "Some problem with connect to database" });
                                (OK_RESPONSE.to_string(), response)
                            }
                        }
                    } else {
                        let response: serde_json::Value =
                            json!({ "Error": "User with this id is not found" });
                        (OK_RESPONSE.to_string(), response)
                    }
                }
                _ => {
                    let response: serde_json::Value = json!({ "Error": "Token is not valid or some problem with connect to database" });
                    (OK_RESPONSE.to_string(), response)
                }
            }
        }
        (Err(error), Ok(_), Ok(_)) => error,
        _ => {
            let response: serde_json::Value = json!({ "Error": "Internal server error" });
            (INTERNAL_SERVER_ERROR.to_string(), response)
        }
    }
}

// добавить валидацию email и name
fn handle_sign_up_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((user, user_info, _user_ach, _friend_list)), Ok(mut client)) => {
            println!("pswd: {:?}", user.pswd.clone());
            println!("Len: {:?}", user.pswd.clone().unwrap_or_default().len());
            match (
                client.query_one(
                    "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                    &[&user.email],
                ),
                client.query_one(SELECT_NICKNAME_SCRIPT, &[&user.email]),
                user.clone().validate(),
                user_info.clone().validate(),
            ) {
                (Ok(check_email), Ok(check_name), Ok(_), Ok(_)) => {
                    let user_email_presence: bool = check_email.get(0);
                    let user_name_presence: bool = check_name.get(0);

                    match (user_email_presence, user_name_presence) {
                        (email_presence, name_presence)
                            if email_presence == false && name_presence == false =>
                        {
                            let hash_pswd = PasswordForDatabase::generate_hash_password(&user);

                            client
                                .execute(INSERT_USER_SCRIPT, &[&hash_pswd, &user.email])
                                .unwrap();
                            client
                                .execute(INSERT_USER_INFO_SCRIPT, &[&user.email, &user_info.name])
                                .unwrap();
                            client
                                .execute(INSERT_ACH_USER_SCRIPT, &[&user.email])
                                .unwrap();

                            let response: serde_json::Value =
                                json!({ "Response": "User registered" });

                            (OK_RESPONSE.to_string(), response)
                        }
                        (email_presence, name_presence)
                            if email_presence == false && name_presence =>
                        {
                            let response: serde_json::Value =
                                json!({ "Error": "This name is already taken" });
                            (OK_RESPONSE.to_string(), response)
                        }
                        (email_presence, name_presence)
                            if email_presence && name_presence == false =>
                        {
                            let response: serde_json::Value =
                                json!({ "Error": "This email is already taken" });
                            (OK_RESPONSE.to_string(), response)
                        }
                        _ => {
                            let response: serde_json::Value =
                                json!({ "Error": "This email or name is already taken" });
                            (OK_RESPONSE.to_string(), response)
                        }
                    }
                }
                (Ok(_), Ok(_), Err(_), Ok(_)) => {
                    let response: serde_json::Value =
                        json!({ "Error": "This user email or pswd is not available" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
                (Ok(_), Ok(_), Ok(_), Err(_)) => {
                    let response: serde_json::Value =
                        json!({ "Error": "This user nickname is not available" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
                _ => {
                    let response: serde_json::Value =
                        json!({ "Error": "Error creating initial table" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
            }
        }
        (Err(error), Ok(_)) => error,
        _ => {
            let response: serde_json::Value = json!({ "Error": "Internal server error" });
            (INTERNAL_SERVER_ERROR.to_string(), response)
        }
    }
}

fn handle_sign_in_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((user, mut user_info, _user_ach, _friend_list)), Ok(mut client)) => {
            match client.query_one(
                "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                &[&user.email],
            ) {
                Ok(email_presence) => {
                    let user_email_presence: bool = email_presence.get(0);

                    if user_email_presence {
                        match client.query_one(SELECT_ROLE_SCRIPT, &[&user.email]) {
                            Ok(user_role) => {
                                user_info.role = Some(user_role.get(0));

                                let verification_complete =
                                    PasswordForDatabase::verify_password(&user, &mut client);

                                if verification_complete {
                                    let token = Claims::create_jwt_token(&user, &user_info); // нужно ли делать проверку, создался ли токен?
                                    let response: serde_json::Value = json!({ "Response": token });
                                    (OK_RESPONSE.to_string(), response)
                                } else {
                                    let response: serde_json::Value =
                                        json!({ "Error": "Wrong email or password" });
                                    (OK_RESPONSE.to_string(), response)
                                }
                            }
                            _ => {
                                let response: serde_json::Value =
                                    json!({ "Error": "Trouble getting role" });
                                (
                                    NOT_FOUND_RESPONSE.to_string(), // изменить на другу ошибку
                                    response,
                                )
                            }
                        }
                    } else {
                        let response: serde_json::Value =
                            json!({ "Error": "There is no user with this email" });
                        (
                            NOT_FOUND_RESPONSE.to_string(), // изменить на другу ошибку
                            response,
                        )
                    }
                }
                _ => {
                    let response: serde_json::Value =
                        json!({ "Error": "Error creating initial table" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
            }
        }
        (Err(error), Ok(_)) => error,
        _ => {
            let response: serde_json::Value = json!({ "Error": "Internal server error" });
            (INTERNAL_SERVER_ERROR.to_string(), response)
        }
    }
}

// use serde_json::{json, Value};
// use validator::Validate;

// use serde::{Deserialize, Serialize};

// #[derive(Debug, Validate, Clone)]
// struct User {
//     id: Option<i32>,
//     pswd: Option<String>,
//     #[validate(email)]
//     email: Option<String>,
// }

// #[derive(Debug, Validate, Clone)]
// struct UserInfo {
//     role: Option<String>,
//     #[validate(required, length(min = 1))]
//     name: Option<String>,
//     training_complete: Option<bool>,
//     mtx_lvl: Option<i16>,
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// struct UserAch {
//     ach: Option<Vec<bool>>,
// }

// fn abc(
//     user: User,
//     user_info: UserInfo,
//     user_ach: UserAch,
// ) -> Result<(User, UserInfo, UserAch), (String, Value)> {
//     // match (user.clone().validate(), user_info.clone().validate()) {
//     //     (Ok(_), Ok(_)) => Ok((user, user_info)),
//     //     (Ok(_), Err(_)) => Err("Yes but No".to_string()),
//     //     (Err(_), Ok(_)) => Err("No but Yes".to_string()),
//     //     _ => Err("no no no".to_string()),
//     // }
//     match (user.clone().validate(), user_info.clone().validate()) {
//         (Ok(_), Ok(_)) => {
//             println!("Что то пошло не так");
//             Ok((user, user_info, user_ach))
//         }
//         (Err(_), Ok(_)) => {
//             let response: serde_json::Value = json!({ "Error": "This email cannot be used" });
//             Err(("OK_RESPONSE".to_string(), response))
//         }
//         (Ok(_), Err(_)) => {
//             let response: serde_json::Value = json!({ "Error": "This name cannot be used" });
//             Err(("OK_RESPONSE".to_string(), response))
//         }
//         _ => {
//             let response: serde_json::Value =
//                 json!({ "Error": "This email and name cannot be used" });
//             Err(("OK_RESPONSE".to_string(), response))
//         }
//     }
// }

// fn main() {
//     let user = User {
//         id: None,
//         pswd: Some("124".to_string()),
//         email: Some("jopa@mail.ru".to_string()),
//     };

//     let user_info = UserInfo {
//         role: None,

//         name: Some("".to_string()),
//         training_complete: Some(false),
//         mtx_lvl: Some(1),
//     };

//     let user_ach = UserAch {
//         ach: Some([].to_vec()),
//     };

//     match abc(user, user_info, user_ach) {
//         Ok((user, _user_info, user_ach)) => {
//             println!("{}", user.email.unwrap())
//         }
//         Err(error) => println!("{:?}", error),
//     }
// }
