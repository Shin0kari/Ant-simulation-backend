use postgres::{Client, NoTls};
use rust_runner::data::handle_req::change_access_request::handle_change_access;
use rust_runner::data::handle_req::func_used_in_req::list_of_status_code::NOT_FOUND_RESPONSE;
use rust_runner::data::handle_req::func_used_in_req::secret_fn::DB_URL;
use rust_runner::data::handle_req::handle_request;
use rust_runner::data::sql_scripts::CREATE_DIAG;
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

    let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
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
                r if (r.starts_with("POST /sign_up")
                    || r.starts_with("POST /sign_in")
                    || r.starts_with("PUT /put_user_data/")
                    || r.starts_with("POST /post_user_friend/")
                    || r.starts_with("DELETE /del_user_friend/")
                    || r.starts_with("GET /get_user_data/")
                    || r.starts_with("DELETE /delete_user/")) =>
                {
                    handle_request(r)
                }
                r if r.starts_with("PUT /change_access/") => handle_change_access(r),
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
