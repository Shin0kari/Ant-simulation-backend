use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use ant_rust_backend_lib::data::{
    handle_req::func_used_in_req::{
        general_func::get_user_request_body,
        list_of_status_code::{INTERNAL_SERVER_ERROR, NOT_FOUND_RESPONSE, OK_RESPONSE},
        secret_fn::{get_env_data, Claims, PasswordForDatabase},
    },
    sql_scripts::select_script::SELECT_ROLE_SCRIPT,
};
use serde_json::json;
use simple_threadpool_func_bio::simple_threadpool_func::ThreadPool;

use postgres::{Client, NoTls};

fn main() {
    let listener = TcpListener::bind("0.0.0.0:5545").unwrap();
    let pool = ThreadPool::new(1);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                pool.execute(|| {
                    handle_sign_in(stream);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

fn handle_sign_in(mut stream: TcpStream) {
    // обработка подключения
    let mut buffer = [0; 1024];
    let mut request = String::new();

    match stream.read(&mut buffer) {
        Ok(size) => {
            request.push_str(String::from_utf8_lossy(&buffer[..size]).as_ref());

            // sleep(time::Duration::from_secs(10));

            let content = match request.as_str() {
                r if !r.to_string().is_empty() => sign_in_request(r),
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

fn sign_in_request(request: &str) -> (String, serde_json::Value) {
    let db_url: &str = &get_env_data("DB_URL");
    match (
        get_user_request_body(request),
        Client::connect(db_url, NoTls),
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

                                    (OK_RESPONSE.to_string(), json!({ "Response": token }))
                                } else {
                                    (
                                        OK_RESPONSE.to_string(),
                                        json!({ "Error": "Wrong email or password" }),
                                    )
                                }
                            }
                            _ => (
                                NOT_FOUND_RESPONSE.to_string(), // изменить на другу ошибку
                                json!({ "Error": "Trouble getting role" }),
                            ),
                        }
                    } else {
                        (
                            NOT_FOUND_RESPONSE.to_string(), // изменить на другу ошибку
                            json!({ "Error": "There is no user with this email" }),
                        )
                    }
                }
                _ => (
                    NOT_FOUND_RESPONSE.to_string(),
                    json!({ "Error": "Error creating initial table" }),
                ),
            }
        }
        (Err(error), Ok(_)) => error,
        _ => (
            INTERNAL_SERVER_ERROR.to_string(),
            json!({ "Error": "Internal server error" }),
        ),
    }
}
