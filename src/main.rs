use postgres::{Client, NoTls};
use rs_crud::data::handle_request::func_used_in_req::list_of_status_code::NOT_FOUND_RESPONSE;
use rs_crud::data::handle_request::func_used_in_req::secret_fn::DB_URL;
use rs_crud::data::sql_scripts::CREATE_DIAG;
use serde_json::json;
// use std::env;
use postgres::Error as PostgresError;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn set_database() -> Result<(), PostgresError> {
    let mut client = Client::connect(DB_URL, NoTls)?;

    client.batch_execute(CREATE_DIAG)?;
    Ok(())
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

use ::rs_crud::data::handle_request::{
    handle_add_friend_request, handle_delete_friend_request, handle_delete_request,
    handle_get_request, handle_put_request, handle_sign_in_request, handle_sign_up_request,
};

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
