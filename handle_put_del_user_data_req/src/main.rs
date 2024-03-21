use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use handle_put_del_user_data_req::{
    data::{
        general_func::{get_id_from_request, get_token_from_request, get_user_request_body},
        list_of_status_code::{INTERNAL_SERVER_ERROR, NOT_FOUND_RESPONSE, OK_RESPONSE},
        not_general_func::{delete_user, update_user},
    },
    secret_fn::{Claims, DB_URL},
};
use postgres::{Client, NoTls};
use serde_json::json;
use simple_threadpool_func_bio::simple_threadpool_func::ThreadPool;
use validator::Validate;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:5547").unwrap();
    let pool = ThreadPool::new(1);

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
                r if (!r.to_string().is_empty() && r.starts_with("POST /post_user_friend/")) => {
                    put_data_request(r)
                }
                r if (!r.to_string().is_empty() && r.starts_with("DELETE /del_user_friend/")) => {
                    del_data_request(r)
                }
                _ => {
                    let response: serde_json::Value = json!({ "Error": "Not found response" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
            };

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
    match (
        get_user_request_body(request),
        get_token_from_request(request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((mut user, mut user_info, user_ach, _friend_list)), Ok(token), Ok(mut client)) => {
            match (
                Claims::verify_token(token),
                user.clone().validate(),
                // user_info.clone().validate(),
            ) {
                (Ok(claims), Ok(_)) => {
                    // возможно изменить на получение роли из бд
                    match claims.role.as_str() {
                        r if r == "user" => {
                            user_info.role = Some(r.to_string());
                            // 2 проверка нужна, если хотим сменить email
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
                                        if !user_email_presence {
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
                        r if r == "admin" => {
                            user_info.role = Some(r.to_string());
                            match get_id_from_request(request).parse::<i32>() {
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
                                                        (presence_email, _actual_email) if !presence_email => {
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
                                            if !user_email_presence {
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
                (Ok(_), Err(_)) => {
                    let response: serde_json::Value =
                        json!({ "Error": "This user email or password is not available" });
                    (OK_RESPONSE.to_string(), response)
                }
                // (Ok(_), Ok(_), Err(_)) => {
                //     let response: serde_json::Value =
                //         json!({ "Error": "This user nickname is not available" });
                //     (OK_RESPONSE.to_string(), response)
                // }
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

fn del_data_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_token_from_request(request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(token), Ok(mut client)) => match Claims::verify_token(token) {
            Ok(claims) => match claims.role.as_str() {
                "user" => {
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
                "admin" => match get_id_from_request(request).parse::<i32>() {
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
                },
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
