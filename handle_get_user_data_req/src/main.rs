use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use handle_get_user_data_req::{
    data::{
        general_func::{get_id_from_request, get_token_from_request},
        list_of_status_code::{INTERNAL_SERVER_ERROR, NOT_FOUND_RESPONSE, OK_RESPONSE},
        not_general_func::read_user,
    },
    secret_fn::{Claims, DB_URL},
};
use serde_json::json;

use postgres::{Client, NoTls};
use simple_threadpool_func_bio::simple_threadpool_func::ThreadPool;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:5546").unwrap();
    let pool = ThreadPool::new(1);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                pool.execute(|| {
                    handle_get_data(stream);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

fn handle_get_data(mut stream: TcpStream) {
    // обработка подключения
    let mut buffer = [0; 1024];
    let mut request = String::new();

    match stream.read(&mut buffer) {
        Ok(size) => {
            request.push_str(String::from_utf8_lossy(&buffer[..size]).as_ref());

            // sleep(time::Duration::from_secs(10));

            let content = match request.as_str() {
                r if !r.to_string().is_empty() => get_data_request(r),
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

fn get_data_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_token_from_request(request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(token), Ok(mut client)) => match Claims::verify_token(token) {
            Ok(claims) => match claims.role.as_str() {
                r if r == "user" => {
                    match client.query_one(
                        "SELECT users.id_user FROM users WHERE users.email = $1",
                        &[&claims.sub],
                    ) {
                        Ok(id) => {
                            let actual_id: i32 = id.get(0);
                            read_user(client, actual_id, r)
                        }
                        _ => {
                            let response: serde_json::Value = json!({ "Error": "Error creating initial table or there is no user with this email" });
                            (OK_RESPONSE.to_string(), response)
                        }
                    }
                }
                r if r == "admin" => match get_id_from_request(request).parse::<i32>() {
                    Ok(get_id) => read_user(client, get_id, r),
                    _ => {
                        match client.query_one(
                            "SELECT users.id_user FROM users WHERE users.email = $1",
                            &[&claims.sub],
                        ) {
                            Ok(get_id) => {
                                let actual_id: i32 = get_id.get(0);
                                read_user(client, actual_id, r)
                            }
                            _ => {
                                let response: serde_json::Value =
                                    json!({ "Error": "Error creating initial table" });
                                (NOT_FOUND_RESPONSE.to_string(), response)
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
