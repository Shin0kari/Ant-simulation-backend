use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use ant_rust_backend_lib::data::handle_req::func_used_in_req::{
    general_func::{get_id_from_request, get_token_from_request, get_user_request_body},
    list_of_status_code::{INTERNAL_SERVER_ERROR, NOT_FOUND_RESPONSE, OK_RESPONSE},
    not_general_func::{delete_user, update_user},
    secret_fn::{get_env_data, Claims},
    user_struct::{User, UserAch, UserInfo},
};

use postgres::{Client, NoTls};
use serde_json::json;
use simple_threadpool_func_bio::simple_threadpool_func::ThreadPool;
use validator::Validate;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:5547").unwrap();
    let pool = ThreadPool::new(3);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                pool.execute(|| {
                    handle_put_del_data(stream);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

fn handle_put_del_data(mut stream: TcpStream) {
    // обработка подключения
    let mut buffer = [0; 1024];
    let mut request = String::new();

    match stream.read(&mut buffer) {
        Ok(size) => {
            request.push_str(String::from_utf8_lossy(&buffer[..size]).as_ref());

            // sleep(time::Duration::from_secs(10));

            let content = match request.as_str() {
                r if (!r.to_string().is_empty() && r.starts_with("PUT /put_user_data/")) => {
                    put_data_request(r)
                }
                r if (!r.to_string().is_empty() && r.starts_with("DELETE /delete_user_data/")) => {
                    del_data_request(r)
                }
                _ => (
                    NOT_FOUND_RESPONSE.to_string(),
                    json!({ "Error": "Not found response" }),
                ),
            };

            // ставлю "//" чтобы потом можно было бы разделить status_line и content
            stream
                .write_all((content.0 + "//" + &content.1.to_string()).as_bytes())
                .unwrap();
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}

fn put_data_request(request: &str) -> (String, serde_json::Value) {
    let db_url: &str = &get_env_data("DB_URL");

    let (mut user, mut user_info, user_ach) = match get_user_request_body(request) {
        Ok(new_user_data) => (new_user_data.0, new_user_data.1, new_user_data.2),
        Err(err) => return err,
    };

    let mut client: Client = match Client::connect(db_url, NoTls) {
        Ok(client_conn) => client_conn,
        Err(_err) => {
            return (
                INTERNAL_SERVER_ERROR.to_string(),
                json!({ "Error": "Error connecting to database" }),
            )
        }
    };

    let token = match get_token_from_request(request) {
        Ok(token) => token,
        Err(_err) => {
            return (
                INTERNAL_SERVER_ERROR.to_string(),
                json!({ "Error": "Error connecting to database" }),
            )
        }
    };

    let claims = match (Claims::verify_token(token), user.clone().validate()) {
        (Ok(claims), Ok(_)) => claims,
        (Ok(_), Err(_)) => {
            return (
                OK_RESPONSE.to_string(),
                json!({ "Error": "This user email or password is not available" }),
            )
        }
        _ => {
            return (
                OK_RESPONSE.to_string(),
                json!({ "Error": "Token is invalid" }),
            )
        }
    };

    match claims.role.as_str() {
        r if r == "user" => {
            user_info.role = Some(r.to_string());
            user_put_req(&mut user, &mut user_info, user_ach, &mut client, &claims)
        }
        r if r == "admin" => {
            user_info.role = Some(r.to_string());
            admin_put_req(
                &mut user,
                &mut user_info,
                user_ach,
                &mut client,
                &claims,
                request,
            )
        }
        _ => (
            OK_RESPONSE.to_string(),
            json!({ "Error": "This role has no privileges" }),
        ),
    }
}

fn user_put_req(
    user: &mut User,
    user_info: &mut UserInfo,
    user_ach: UserAch,
    client: &mut Client,
    claims: &Claims,
) -> (String, serde_json::Value) {
    let check_email = match client.query_one(
        "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
        &[&user.email],
    ) {
        Ok(check_email) => check_email,
        Err(_err) => {
            return (
                INTERNAL_SERVER_ERROR.to_string(),
                json!({ "Error": "Error connecting to database" }),
            )
        }
    };
    let id = match client.query_one(
        "SELECT users.id_user FROM users WHERE users.email = $1",
        &[&claims.sub],
    ) {
        Ok(id) => id,
        Err(_err) => {
            return (
                INTERNAL_SERVER_ERROR.to_string(),
                json!({ "Error": "There is no user with this id" }),
            )
        }
    };

    let user_email_presence: bool = check_email.get(0);
    let actual_id: i32 = id.get(0);

    if user.email != Some(claims.sub.clone()) {
        if !user_email_presence {
            update_user(user, user_info, user_ach, client, actual_id)
        } else {
            (
                OK_RESPONSE.to_string(),
                json!({ "Error": "This email is already taken" }),
            )
        }
    } else {
        update_user(user, user_info, user_ach, client, actual_id)
    }
}

fn admin_put_req(
    user: &mut User,
    user_info: &mut UserInfo,
    user_ach: UserAch,
    client: &mut Client,
    claims: &Claims,
    request: &str,
) -> (String, serde_json::Value) {
    match get_id_from_request(request).parse::<i32>() {
        Ok(get_id) => {
            let check_id: bool = match client.query_one(
                "SELECT EXISTS(SELECT users.id_user FROM users WHERE users.id_user = $1)",
                &[&get_id],
            ) {
                Ok(check_id) => check_id.get(0),
                _ => {
                    return (
                        OK_RESPONSE.to_string(),
                        json!({ "Error": "Error creating initial table" }),
                    )
                }
            };

            if !check_id {
                return (
                    OK_RESPONSE.to_string(),
                    json!({ "Error": "There is no user with this id" }),
                );
            }

            let check_mail: bool = match client.query_one(
                "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                &[&user.email],
            ) {
                Ok(check_mail) => check_mail.get(0),
                _ => {
                    return (
                        OK_RESPONSE.to_string(),
                        json!({ "Error": "Error creating initial table" }),
                    )
                }
            };

            let get_mail: String = match client.query_one(
                "SELECT users.email FROM users WHERE users.id_user = $1",
                &[&get_id],
            ) {
                Ok(get_mail) => get_mail.get(0),
                _ => {
                    return (
                        OK_RESPONSE.to_string(),
                        json!({ "Error": "Error creating initial table" }),
                    )
                }
            };

            match (check_mail, get_mail) {
                (presence_email, actual_email)
                    if presence_email && actual_email == user.email.clone().unwrap() =>
                {
                    update_user(user, user_info, user_ach, client, get_id)
                }
                (presence_email, _actual_email) if !presence_email => {
                    update_user(user, user_info, user_ach, client, get_id)
                }
                _ => (
                    OK_RESPONSE.to_string(),
                    json!({ "Error": "This email is already taken" }),
                ),
            }
        }
        _ => user_put_req(user, user_info, user_ach, client, claims),
    }
}

// fn put_data_request(request: &str) -> (String, serde_json::Value) {
//     let db_url: &str = &get_env_data("DB_URL");
//     match (
//         get_user_request_body(request),
//         get_token_from_request(request),
//         Client::connect(db_url, NoTls),
//     ) {
//         (Ok((mut user, mut user_info, user_ach, _friend_list)), Ok(token), Ok(mut client)) => {
//             match (Claims::verify_token(token), user.clone().validate()) {
//                 (Ok(claims), Ok(_)) => {
//                     // возможно изменить на получение роли из бд
//                     match claims.role.as_str() {
//                         r if r == "user" => {
//                             user_info.role = Some(r.to_string());
//                             // 2 проверка нужна, если хотим сменить email
//                             match (
//                                 client.query_one(
//                                 "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
//                                 &[&user.email]),
//                                 client.query_one("SELECT users.id_user FROM users WHERE users.email = $1", &[&claims.sub]),
//                             ) {
//                                 (Ok(check_email), Ok(id)) => {
//                                     let user_email_presence: bool = check_email.get(0);
//                                     let actual_id: i32 = id.get(0);

//                                     if user.email != Some(claims.sub) {
//                                         if !user_email_presence {
//                                             update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
//                                         } else {
//                                             (OK_RESPONSE.to_string(), json!({ "Error": "This email is already taken" }))
//                                         }
//                                     } else {
//                                         update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
//                                     }
//                                 }
//                                 _ => {
//                                     (OK_RESPONSE.to_string(), json!({ "Error": "Error creating initial table or there is no user with this id" }))
//                                 }
//                             }
//                         }
//                         r if r == "admin" => {
//                             user_info.role = Some(r.to_string());
//                             match get_id_from_request(request).parse::<i32>() {
//                                 Ok(get_id) => {
//                                     // изменяет кого-то
//                                     match client.query_one("SELECT EXISTS(SELECT users.id_user FROM users WHERE users.id_user = $1)",
//                                     &[&get_id]) {
//                                     Ok(check_id) => {
//                                         let user_id_presence: bool = check_id.get(0);

//                                         if user_id_presence {
//                                             // 1-ое для проверки, чтобы не поменяли на тот же email, 2-ое для получения email пользователя
//                                             match (client.query_one("SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
//                                                 &[&user.email]),
//                                                 client.query_one("SELECT users.email FROM users WHERE users.id_user = $1", &[&get_id]),
//                                             ) {
//                                                 (Ok(check_email), Ok(get_email)) => {
//                                                     let user_email_presence: bool = check_email.get(0);
//                                                     let get_user_email: String = get_email.get(0);

//                                                     match (user_email_presence, get_user_email) {
//                                                         (presence_email, actual_email) if presence_email && actual_email == user.email.clone().unwrap() => {
//                                                             update_user(&mut user, &mut user_info, user_ach, &mut client, get_id)
//                                                         }
//                                                         (presence_email, _actual_email) if !presence_email => {
//                                                             update_user(&mut user, &mut user_info, user_ach, &mut client, get_id)
//                                                         }
//                                                         _ => {
//                                                             (OK_RESPONSE.to_string(), json!({ "Error": "This email is already taken" }))
//                                                         }
//                                                     }
//                                                 }
//                                                 _ => {
//                                                     (OK_RESPONSE.to_string(), json!({ "Error": "Error creating initial table" }))
//                                                 }
//                                             }
//                                         } else {
//                                             (OK_RESPONSE.to_string(), json!({ "Error": "There is no user with this id" }))
//                                         }
//                                     }
//                                     _ => {
//                                         (OK_RESPONSE.to_string(), json!({ "Error": "Error creating initial table" }))
//                                     }
//                                 }
//                                 }
//                                 _ => {
//                                     match (
//                                     client.query_one("SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
//                                     &[&user.email]),
//                                     client.query_one("SELECT users.id_user FROM users WHERE users.email = $1",
//                                     &[&claims.sub]),) {
//                                     (Ok(check_email), Ok(get_id)) => {
//                                         let user_email_presence: bool = check_email.get(0);
//                                         let actual_id: i32 = get_id.get(0);
//                                                 // изменённый email и истинный email
//                                         if user.email != Some(claims.sub) {
//                                             if !user_email_presence {
//                                                 update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
//                                             } else {
//                                                 (OK_RESPONSE.to_string(), json!({ "Error": "This email is already taken" }))
//                                             }
//                                         } else {
//                                             update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
//                                         }
//                                     }
//                                     _ => {
//                                         (OK_RESPONSE.to_string(), json!({ "Error": "Error creating initial table" }))
//                                     }
//                                 }
//                                 }
//                             }
//                         }
//                         _ => (
//                             OK_RESPONSE.to_string(),
//                             json!({ "Error": "This role has no privileges" }),
//                         ),
//                     }
//                 }
//                 (Ok(_), Err(_)) => (
//                     OK_RESPONSE.to_string(),
//                     json!({ "Error": "This user email or password is not available" }),
//                 ),
//                 _ => (
//                     OK_RESPONSE.to_string(),
//                     json!({ "Error": "Token is invalid" }),
//                 ),
//             }
//         }
//         (Err(error), Ok(_), Ok(_)) => error,
//         _ => (
//             INTERNAL_SERVER_ERROR.to_string(),
//             json!({ "Error": "Internal server error" }),
//         ),
//     }
// }

fn del_data_request(request: &str) -> (String, serde_json::Value) {
    let db_url: &str = &get_env_data("DB_URL");

    let mut client: Client = match Client::connect(db_url, NoTls) {
        Ok(client_conn) => client_conn,
        Err(_err) => {
            return (
                INTERNAL_SERVER_ERROR.to_string(),
                json!({ "Error": "Error connecting to database" }),
            )
        }
    };

    let token = match get_token_from_request(request) {
        Ok(token) => token,
        Err(_err) => {
            return (
                INTERNAL_SERVER_ERROR.to_string(),
                json!({ "Error": "Error connecting to database" }),
            )
        }
    };

    let claims = match Claims::verify_token(token) {
        Ok(claims) => claims,
        _ => {
            return (
                OK_RESPONSE.to_string(),
                json!({ "Error": "Token is invalid" }),
            )
        }
    };

    match claims.role.as_str() {
        "user" => del_user_req(claims, &mut client),
        "admin" => match get_id_from_request(request).parse::<i32>() {
            Ok(get_id) => delete_user(&mut client, get_id),
            _ => del_user_req(claims, &mut client),
        },
        _ => (
            OK_RESPONSE.to_string(),
            json!({ "Error": "This role has no privileges" }),
        ),
    }
}

fn del_user_req(claims: Claims, client: &mut Client) -> (String, serde_json::Value) {
    match client.query_one(
        "SELECT users.id_user FROM users WHERE users.email = $1",
        &[&claims.sub],
    ) {
        Ok(id) => {
            let actual_id: i32 = id.get(0);
            delete_user(client, actual_id)
        }
        _ => (
            OK_RESPONSE.to_string(),
            json!({ "Error": "Error creating initial table or there is no user with this email" }),
        ),
    }
}

// fn del_data_request(request: &str) -> (String, serde_json::Value) {
//     let db_url: &str = &get_env_data("DB_URL");
//     match (
//         get_token_from_request(request),
//         Client::connect(db_url, NoTls),
//     ) {
//         (Ok(token), Ok(mut client)) => match Claims::verify_token(token) {
//             Ok(claims) => match claims.role.as_str() {
//                 "user" => {
//                     match client.query_one(
//                         "SELECT users.id_user FROM users WHERE users.email = $1",
//                         &[&claims.sub],
//                     ) {
//                         Ok(id) => {
//                             let actual_id: i32 = id.get(0);
//                             delete_user(client, actual_id)
//                         }
//                         _ => (
//                             OK_RESPONSE.to_string(),
//                             json!({ "Error": "Error creating initial table or there is no user with this email" }),
//                         ),
//                     }
//                 }
//                 "admin" => match get_id_from_request(request).parse::<i32>() {
//                     Ok(get_id) => delete_user(client, get_id),
//                     _ => {
//                         match client.query_one(
//                             "SELECT users.id_user FROM users WHERE users.email = $1",
//                             &[&claims.sub],
//                         ) {
//                             Ok(get_id) => {
//                                 let actual_id: i32 = get_id.get(0);
//                                 delete_user(client, actual_id)
//                             }
//                             _ => (
//                                 OK_RESPONSE.to_string(),
//                                 json!({ "Error": "Error creating initial table" }),
//                             ),
//                         }
//                     }
//                 },
//                 _ => (
//                     OK_RESPONSE.to_string(),
//                     json!({ "Error": "This role has no privileges" }),
//                 ),
//             },
//             _ => (
//                 OK_RESPONSE.to_string(),
//                 json!({ "Error": "Token is invalid" }),
//             ),
//         },
//         _ => (
//             INTERNAL_SERVER_ERROR.to_string(),
//             json!({ "Error": "Internal server error" }),
//         ),
//     }
// }
