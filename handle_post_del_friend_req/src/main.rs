use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use ant_rust_backend_lib::data::{
    handle_req::func_used_in_req::{
        general_func::{get_token_from_request, get_user_request_body},
        list_of_status_code::{INTERNAL_SERVER_ERROR, NOT_FOUND_RESPONSE, OK_RESPONSE},
        secret_fn::{Claims, DB_URL},
    },
    sql_scripts::{delete_script::DELETE_FRIEND_SCRIPT, insert_script::INSERT_FRIEND_LIST_SCRIPT},
};

use postgres::{Client, NoTls};
use serde_json::json;
use simple_threadpool_func_bio::simple_threadpool_func::ThreadPool;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:5548").unwrap();
    let pool = ThreadPool::new(1);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                pool.execute(|| {
                    handle_post_del_friend(stream);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

fn handle_post_del_friend(mut stream: TcpStream) {
    // обработка подключения
    let mut buffer = [0; 1024];
    let mut request = String::new();

    match stream.read(&mut buffer) {
        Ok(size) => {
            request.push_str(String::from_utf8_lossy(&buffer[..size]).as_ref());

            // sleep(time::Duration::from_secs(10));

            let content = match request.as_str() {
                r if (!r.to_string().is_empty() && r.starts_with("POST /post_user_friend/")) => {
                    post_friend_request(r)
                }
                r if (!r.to_string().is_empty() && r.starts_with("DELETE /del_user_friend/")) => {
                    del_friend_request(r)
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

fn post_friend_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(request),
        get_token_from_request(request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((_user, _user_info, _user_ach, friend_list)), Ok(token), Ok(mut client)) => {
            match (
                Claims::verify_token(token),
                client.query_one(
                    "SELECT EXISTS(SELECT users.src/data/handle_request/func_used_in_req/general_func.rsemail FROM users WHERE users.email = $1)",
                    &[&friend_list.friend_email],
                ),
            ) {
                (Ok(claims), Ok(check_email)) => {
                    let friend_email_presence: bool = check_email.get(0);

                    if friend_email_presence {
                        match (
                            client.query_one(
                                "SELECT users.id_user FROM users WHERE users.email = $1",
                                &[&claims.sub],
                            ),
                            client.query_one(
                                "SELECT users.id_user FROM users WHERE users.email = $1",
                                &[&friend_list.friend_email],
                            ),
                        ) {
                            (Ok(user_id), Ok(friend_id)) => {
                                let actual_id: i32 = user_id.get(0);
                                let friend_id: i32 = friend_id.get(0);
                                match client.query_one(
                                    "SELECT EXISTS(SELECT friend_list.friend_id FROM friend_list WHERE id_user = $2 AND friend_id = $1)",
                                    &[&friend_id, &actual_id],
                                ) {
                                    Ok(check_if_friend_in_friend_list) => {
                                        let check_friend: bool = check_if_friend_in_friend_list.get(0);
                                        if !check_friend && actual_id != friend_id {
                                            client
                                                .execute(
                                                    INSERT_FRIEND_LIST_SCRIPT,
                                                    &[&friend_id, &actual_id],
                                                )
                                                .unwrap();
                                            let response: serde_json::Value =
                                                json!({ "Response": "Friend added to friends list" });
                                            (OK_RESPONSE.to_string(), response)
                                        } else if actual_id == friend_id {
                                            let response: serde_json::Value =
                                                json!({ "Error": "You are trying to add your email to your friends list" });
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
                            json!({ "Error": "User with this email is not found" });
                        (OK_RESPONSE.to_string(), response)
                    }
                }
                (Ok(_), Err(_)) => {
                    let response: serde_json::Value = json!({ "Error": "User is not found or some problem with connect to database" });
                    (OK_RESPONSE.to_string(), response)
                }
                (Err(_), Ok(_)) => {
                    let response: serde_json::Value = json!({ "Error": "Token is not valid" });
                    (OK_RESPONSE.to_string(), response)
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

fn del_friend_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(request),
        get_token_from_request(request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((_user, _user_info, _user_ach, friend_list)), Ok(token), Ok(mut client)) => {
            match Claims::verify_token(token) {
                Ok(claims) => {
                    match (
                        client.query_one(
                            "SELECT users.id_user FROM users WHERE users.email = $1",
                            &[&claims.sub],
                        ),
                        client.query_one(
                            "SELECT users.id_user FROM users WHERE users.email = $1",
                            &[&friend_list.friend_email],
                        ),
                    ) {
                        (Ok(user_id), Ok(friend_id)) => {
                            let actual_id: i32 = user_id.get(0);
                            let friend_id: i32 = friend_id.get(0);
                            match client.query_one(
                                "SELECT EXISTS(SELECT friend_list.friend_id FROM friend_list WHERE id_user = $2 AND friend_id = $1)",
                                &[&friend_id, &actual_id],
                            ) {
                                Ok(check_if_friend_in_friend_list) => {
                                    let check_friend: bool = check_if_friend_in_friend_list.get(0);
                                    if check_friend {
                                        client
                                            .execute(
                                                DELETE_FRIEND_SCRIPT,
                                                &[&friend_id, &actual_id],
                                            )
                                            .unwrap();
                                        let response: serde_json::Value =
                                            json!({ "Response": "User removed from your friends list" });
                                        (OK_RESPONSE.to_string(), response)
                                    } else {
                                        let response: serde_json::Value =
                                            json!({ "Error": "There is no friend with this email in your friends list" });
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
                        (Ok(_user_id), Err(_error)) => {
                            let response: serde_json::Value =
                                json!({ "Error": "This user has already been deleted" });
                            (OK_RESPONSE.to_string(), response)
                        }
                        (Err(_error), Ok(_friend_id)) => {
                            let response: serde_json::Value = json!({ "Error": "This user has already been removed from your friends list" });
                            (OK_RESPONSE.to_string(), response)
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
