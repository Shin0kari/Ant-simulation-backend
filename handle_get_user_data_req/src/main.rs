use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

use ant_rust_backend_lib::data::handle_req::func_used_in_req::{
    general_func::{get_id_from_request, get_token_from_request},
    list_of_status_code::{INTERNAL_SERVER_ERROR, NOT_FOUND_RESPONSE, OK_RESPONSE},
    not_general_func::read_user,
    secret_fn::{get_env_data, Claims},
};

use serde_json::json;

use postgres::{Client, NoTls};
use simple_threadpool_func_bio::simple_threadpool_func::ThreadPool;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:5546").unwrap();
    let pool = ThreadPool::new(2);

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

fn get_data_request(request: &str) -> (String, serde_json::Value) {
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
        r if r == "user" => user_get_req(&mut client, &claims, r),
        r if r == "admin" => admin_get_req(&mut client, &claims, r, request),
        _ => (
            OK_RESPONSE.to_string(),
            json!({ "Error": "This role has no privileges" }),
        ),
    }
}

fn user_get_req(client: &mut Client, claims: &Claims, root: &str) -> (String, serde_json::Value) {
    let user_id: i32 = match client.query_one(
        "SELECT users.id_user FROM users WHERE users.email = $1",
        &[&claims.sub],
    ) {
        Ok(id) => id.get(0),
        _ => {
            return (
                OK_RESPONSE.to_string(),
                json!({ "Error": "Error creating initial table or there is no user with this email" }),
            )
        }
    };
    read_user(client, user_id, root)
}

fn admin_get_req(
    client: &mut Client,
    claims: &Claims,
    root: &str,
    request: &str,
) -> (String, serde_json::Value) {
    match get_id_from_request(request).parse::<i32>() {
        Ok(get_id) => read_user(client, get_id, root),
        _ => user_get_req(client, claims, root),
    }
}

// fn get_data_request(request: &str) -> (String, serde_json::Value) {
//     let db_url: &str = &get_env_data("DB_URL");
//     match (
//         get_token_from_request(request),
//         Client::connect(db_url, NoTls),
//     ) {
//         (Ok(token), Ok(mut client)) => match Claims::verify_token(token) {
//             Ok(claims) => match claims.role.as_str() {
//                 r if r == "user" => {
//                     match client.query_one(
//                         "SELECT users.id_user FROM users WHERE users.email = $1",
//                         &[&claims.sub],
//                     ) {
//                         Ok(id) => {
//                             let actual_id: i32 = id.get(0);
//                             read_user(client, actual_id, r)
//                         }
//                         _ => (
//                             OK_RESPONSE.to_string(),
//                             json!({ "Error": "Error creating initial table or there is no user with this email" }),
//                         ),
//                     }
//                 }
//                 r if r == "admin" => match get_id_from_request(request).parse::<i32>() {
//                     Ok(get_id) => read_user(client, get_id, r),
//                     _ => {
//                         match client.query_one(
//                             "SELECT users.id_user FROM users WHERE users.email = $1",
//                             &[&claims.sub],
//                         ) {
//                             Ok(get_id) => {
//                                 let actual_id: i32 = get_id.get(0);
//                                 read_user(client, actual_id, r)
//                             }
//                             _ => (
//                                 NOT_FOUND_RESPONSE.to_string(),
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
