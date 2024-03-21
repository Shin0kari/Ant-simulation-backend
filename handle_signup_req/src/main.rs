use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use ant_rust_backend_lib::data::{
    handle_req::func_used_in_req::{
        general_func::get_user_request_body,
        list_of_status_code::{INTERNAL_SERVER_ERROR, NOT_FOUND_RESPONSE, OK_RESPONSE},
        secret_fn::{PasswordForDatabase, DB_URL},
    },
    sql_scripts::insert_script::{
        INSERT_ACH_USER_SCRIPT, INSERT_USER_INFO_SCRIPT, INSERT_USER_SCRIPT,
    },
};

use serde_json::json;
use simple_threadpool_func_bio::simple_threadpool_func::ThreadPool;

use validator::Validate;

use postgres::{Client, NoTls};

fn main() {
    let listener = TcpListener::bind("0.0.0.0:5544").unwrap();
    let pool = ThreadPool::new(1);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                pool.execute(|| {
                    handle_sign_up(stream);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

fn handle_sign_up(mut stream: TcpStream) {
    // обработка подключения
    let mut buffer = [0; 1024];
    let mut request = String::new();

    match stream.read(&mut buffer) {
        Ok(size) => {
            request.push_str(String::from_utf8_lossy(&buffer[..size]).as_ref());

            // sleep(time::Duration::from_secs(10));

            let (status_line, content) = match request.as_str() {
                r if !r.to_string().is_empty() => sign_up_request(r),
                _ => {
                    let response: serde_json::Value = json!({ "Error": "Not found response" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
            };

            stream
                .write_all((status_line + "//" + &content.to_string()).as_bytes())
                .unwrap();
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}

fn sign_up_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((user, _user_info, _user_ach, _friend_list)), Ok(mut client)) => {
            match (
                client.query_one(
                    "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                    &[&user.email],
                ),
                user.clone().validate(),
            ) {
                (Ok(check_email), Ok(_)) => {
                    let user_email_presence: bool = check_email.get(0);

                    if !user_email_presence {
                        let hash_pswd = PasswordForDatabase::generate_hash_password(&user);

                        // добавить match, чтобы сделать проверку, прошли ли все изменения без ошибок, в ином случае чтобы изменения отменились
                        // скорее всего добавлять в файл не прошедшие изменения
                        client
                            .execute(INSERT_USER_SCRIPT, &[&hash_pswd, &user.email])
                            .unwrap();
                        client
                            .execute(INSERT_USER_INFO_SCRIPT, &[&user.email])
                            .unwrap();
                        client
                            .execute(INSERT_ACH_USER_SCRIPT, &[&user.email])
                            .unwrap();

                        let response: serde_json::Value = json!({ "Response": "User registered" });

                        (OK_RESPONSE.to_string(), response)
                    } else {
                        let response: serde_json::Value =
                            json!({ "Error": "This email is already taken" });
                        (OK_RESPONSE.to_string(), response)
                    }
                }
                (Ok(_), Err(_)) => {
                    let response: serde_json::Value =
                        json!({ "Error": "This user email or pswd is not available" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
                _ => {
                    let response: serde_json::Value =
                        json!({ "Error": "Error creating initial table" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
            }
        }
        (Ok(_), Err(_)) => {
            panic!("Error connecting to database");
        }
        _ => {
            let response: serde_json::Value = json!({ "Error": "Internal server error" });
            (INTERNAL_SERVER_ERROR.to_string(), response)
        }
    }
}
