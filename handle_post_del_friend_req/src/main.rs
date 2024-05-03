use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use ant_rust_backend_lib::data::{
    handle_req::func_used_in_req::{
        general_func::{get_token_from_request, get_user_request_body},
        list_of_status_code::{INTERNAL_SERVER_ERROR, NOT_FOUND_RESPONSE, OK_RESPONSE},
        secret_fn::{get_env_data, Claims},
    },
    sql_scripts::{delete_script::DELETE_FRIEND_SCRIPT, insert_script::INSERT_FRIEND_LIST_SCRIPT},
};

use validator::Validate;

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

fn post_friend_request(request: &str) -> (String, serde_json::Value) {
    let db_url: &str = &get_env_data("DB_URL");

    let friend_list = match get_user_request_body(request) {
        Ok(new_user_data) => new_user_data.3,
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

    let claims = match Claims::verify_token(token) {
        Ok(claims) => claims,
        _ => {
            return (
                OK_RESPONSE.to_string(),
                json!({ "Error": "Token is invalid" }),
            )
        }
    };

    if friend_list.clone().validate().is_err() {
        return (
            OK_RESPONSE.to_string(),
            json!({ "Error": "The email provided is not valid" }),
        );
    }

    let friend_email_presence: bool = match client.query_one(
        "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
        &[&friend_list.friend_email],
    ) {
        Ok(check_email) => check_email.get(0),
        _ => {
            return (
                INTERNAL_SERVER_ERROR.to_string(),
                json!({ "Error": "Error creating initial table" }),
            )
        }
    };

    if !friend_email_presence {
        return (
            OK_RESPONSE.to_string(),
            json!({ "Error": "User with this email is not found" }),
        );
    };

    let (user_id, friend_id): (i32, i32) = match (
        client.query_one(
            "SELECT users.id_user FROM users WHERE users.email = $1",
            &[&claims.sub],
        ),
        client.query_one(
            "SELECT users.id_user FROM users WHERE users.email = $1",
            &[&friend_list.friend_email],
        ),
    ) {
        (Ok(user_id), Ok(friend_id)) => (user_id.get(0), friend_id.get(0)),
        _ => {
            return (
                OK_RESPONSE.to_string(),
                json!({ "Error": "Some problem with connect to database" }),
            )
        }
    };

    let check_if_friend_in_friend_list: bool = match client.query_one(
        "SELECT EXISTS(SELECT friend_list.friend_id FROM friend_list WHERE id_user = $2 AND friend_id = $1)",
        &[&friend_id, &user_id],
    ) {
        Ok(check_if_friend_in_friend_list) => check_if_friend_in_friend_list.get(0),
        _ => {
            return (OK_RESPONSE.to_string(), json!({ "Error": "Some problem with connect to database" }))
        }
    };

    if !check_if_friend_in_friend_list && user_id != friend_id {
        client
            .execute(INSERT_FRIEND_LIST_SCRIPT, &[&friend_id, &user_id])
            .unwrap();

        (
            OK_RESPONSE.to_string(),
            json!({ "Response": "Friend added to friends list" }),
        )
    } else if user_id == friend_id {
        (
            OK_RESPONSE.to_string(),
            json!({ "Error": "You are trying to add your email to your friends list" }),
        )
    } else {
        (
            OK_RESPONSE.to_string(),
            json!({ "Error": "Friend has already been added to the friends list" }),
        )
    }
}

// fn post_friend_request(request: &str) -> (String, serde_json::Value) {
//     let db_url: &str = &get_env_data("DB_URL");
//     match (
//         get_user_request_body(request),
//         get_token_from_request(request),
//         Client::connect(db_url, NoTls),
//     ) {
//         (Ok((_user, _user_info, _user_ach, friend_list)), Ok(token), Ok(mut client)) => {
//             match (
//                 Claims::verify_token(token),
//                 client.query_one(
//                     "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
//                     &[&friend_list.friend_email],
//                 ),
//             ) {
//                 (Ok(claims), Ok(check_email)) => {
//                     let friend_email_presence: bool = check_email.get(0);

//                     if friend_email_presence {
//                         match (
//                             client.query_one(
//                                 "SELECT users.id_user FROM users WHERE users.email = $1",
//                                 &[&claims.sub],
//                             ),
//                             client.query_one(
//                                 "SELECT users.id_user FROM users WHERE users.email = $1",
//                                 &[&friend_list.friend_email],
//                             ),
//                         ) {
//                             (Ok(user_id), Ok(friend_id)) => {
//                                 let actual_id: i32 = user_id.get(0);
//                                 let friend_id: i32 = friend_id.get(0);
//                                 match client.query_one(
//                                     "SELECT EXISTS(SELECT friend_list.friend_id FROM friend_list WHERE id_user = $2 AND friend_id = $1)",
//                                     &[&friend_id, &actual_id],
//                                 ) {
//                                     Ok(check_if_friend_in_friend_list) => {
//                                         let check_friend: bool = check_if_friend_in_friend_list.get(0);
//                                         if !check_friend && actual_id != friend_id {
//                                             client
//                                                 .execute(
//                                                     INSERT_FRIEND_LIST_SCRIPT,
//                                                     &[&friend_id, &actual_id],
//                                                 )
//                                                 .unwrap();

//                                             (OK_RESPONSE.to_string(), json!({ "Response": "Friend added to friends list" }))
//                                         } else if actual_id == friend_id {
//                                             (OK_RESPONSE.to_string(), json!({ "Error": "You are trying to add your email to your friends list" }))
//                                         } else {
//                                             (OK_RESPONSE.to_string(), json!({ "Error": "Friend has already been added to the friends list" }))
//                                         }
//                                     }
//                                     _ => {
//                                         (OK_RESPONSE.to_string(), json!({ "Error": "Some problem with connect to database" }))
//                                     }
//                                 }
//                             }
//                             _ => {
//                                 (OK_RESPONSE.to_string(), json!({ "Error": "Some problem with connect to database" }))
//                             }
//                         }
//                     } else {
//                         (OK_RESPONSE.to_string(), json!({ "Error": "User with this email is not found" }))
//                     }
//                 }
//                 (Ok(_), Err(_)) => {
//                     (OK_RESPONSE.to_string(), json!({ "Error": "User is not found or some problem with connect to database" }))
//                 }
//                 (Err(_), Ok(_)) => {
//                     (OK_RESPONSE.to_string(), json!({ "Error": "Token is not valid" }))
//                 }
//                 _ => {
//                     (OK_RESPONSE.to_string(), json!({ "Error": "Token is not valid or some problem with connect to database" }))
//                 }
//             }
//         }
//         (Err(error), Ok(_), Ok(_)) => error,
//         _ => {
//             (INTERNAL_SERVER_ERROR.to_string(), json!({ "Error": "Internal server error" }))
//         }
//     }
// }

fn del_friend_request(request: &str) -> (String, serde_json::Value) {
    let db_url: &str = &get_env_data("DB_URL");

    let friend_list = match get_user_request_body(request) {
        Ok(new_user_data) => new_user_data.3,
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

    let claims = match Claims::verify_token(token) {
        Ok(claims) => claims,
        _ => {
            return (
                OK_RESPONSE.to_string(),
                json!({ "Error": "Token is invalid" }),
            )
        }
    };

    if friend_list.clone().validate().is_err() {
        return (
            OK_RESPONSE.to_string(),
            json!({ "Error": "The email provided is not valid" }),
        );
    }

    let (user_id, friend_id): (i32, i32) = match (
        client.query_one(
            "SELECT users.id_user FROM users WHERE users.email = $1",
            &[&claims.sub],
        ),
        client.query_one(
            "SELECT users.id_user FROM users WHERE users.email = $1",
            &[&friend_list.friend_email],
        ),
    ) {
        (Ok(user_id), Ok(friend_id)) => (user_id.get(0), friend_id.get(0)),
        _ => {
            return (
                OK_RESPONSE.to_string(),
                json!({ "Error": "Some problem with connect to database" }),
            )
        }
    };

    let check_if_friend_in_friend_list: bool = match client.query_one(
        "SELECT EXISTS(SELECT friend_list.friend_id FROM friend_list WHERE id_user = $2 AND friend_id = $1)",
        &[&friend_id, &user_id],
    ) {
        Ok(check_if_friend_in_friend_list) => check_if_friend_in_friend_list.get(0),
        _ => {
            return (OK_RESPONSE.to_string(), json!({ "Error": "Some problem with connect to database" }))
        }
    };

    if check_if_friend_in_friend_list {
        client
            .execute(DELETE_FRIEND_SCRIPT, &[&friend_id, &user_id])
            .unwrap();

        (
            OK_RESPONSE.to_string(),
            json!({ "Response": "User removed from your friends list" }),
        )
    } else {
        (
            OK_RESPONSE.to_string(),
            json!({ "Error": "There is no friend with this email in your friends list" }),
        )
    }
}

// fn del_friend_request(request: &str) -> (String, serde_json::Value) {
//     let db_url: &str = &get_env_data("DB_URL");
//     match (
//         get_user_request_body(request),
//         get_token_from_request(request),
//         Client::connect(db_url, NoTls),
//     ) {
//         (Ok((_user, _user_info, _user_ach, friend_list)), Ok(token), Ok(mut client)) => {
//             match Claims::verify_token(token) {
//                 Ok(claims) => {
//                     match (
//                         client.query_one(
//                             "SELECT users.id_user FROM users WHERE users.email = $1",
//                             &[&claims.sub],
//                         ),
//                         client.query_one(
//                             "SELECT users.id_user FROM users WHERE users.email = $1",
//                             &[&friend_list.friend_email],
//                         ),
//                     ) {
//                         (Ok(user_id), Ok(friend_id)) => {
//                             let actual_id: i32 = user_id.get(0);
//                             let friend_id: i32 = friend_id.get(0);
//                             match client.query_one(
//                                 "SELECT EXISTS(SELECT friend_list.friend_id FROM friend_list WHERE id_user = $2 AND friend_id = $1)",
//                                 &[&friend_id, &actual_id],
//                             ) {
//                                 Ok(check_if_friend_in_friend_list) => {
//                                     let check_friend: bool = check_if_friend_in_friend_list.get(0);
//                                     if check_friend {
//                                         client
//                                             .execute(
//                                                 DELETE_FRIEND_SCRIPT,
//                                                 &[&friend_id, &actual_id],
//                                             )
//                                             .unwrap();

//                                         (OK_RESPONSE.to_string(), json!({ "Response": "User removed from your friends list" }))
//                                     } else {
//                                         (OK_RESPONSE.to_string(), json!({ "Error": "There is no friend with this email in your friends list" }))
//                                     }
//                                 }
//                                 _ => {
//                                     (OK_RESPONSE.to_string(), json!({ "Error": "Some problem with connect to database" }))
//                                 }
//                             }
//                         }
//                         (Ok(_user_id), Err(_error)) => (
//                             OK_RESPONSE.to_string(),
//                             json!({ "Error": "This user has already been deleted" }),
//                         ),
//                         (Err(_error), Ok(_friend_id)) => (
//                             OK_RESPONSE.to_string(),
//                             json!({ "Error": "This user has already been removed from your friends list" }),
//                         ),
//                         _ => (
//                             OK_RESPONSE.to_string(),
//                             json!({ "Error": "Some problem with connect to database" }),
//                         ),
//                     }
//                 }
//                 _ => (
//                     OK_RESPONSE.to_string(),
//                     json!({ "Error": "Token is not valid or some problem with connect to database" }),
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
