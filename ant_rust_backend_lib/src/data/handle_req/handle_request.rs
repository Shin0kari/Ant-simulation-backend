use std::{
    io::{Read, Write},
    net::TcpStream,
};

use serde_json::{json, Value};

use crate::data::handle_req::func_used_in_req::list_of_status_code::NOT_FOUND_RESPONSE;

use super::func_used_in_req::not_general_func::check_access;

fn get_address(request: &str) -> Result<&str, &str> {
    let address: &str = request
        .split(' ')
        .nth(1)
        .unwrap_or_default()
        .split('/')
        .nth(1)
        .unwrap_or_default();

    match address {
        "sign_up" => Ok("rust_sign_up:5544"),
        "sign_in" => Ok("rust_sign_in:5545"),
        "get_user_data" => Ok("rust_get_user_data:5546"),
        "put_user_data" | "delete_user_data" => Ok("rust_put_del_user_data:5547"),
        "post_user_friend" | "del_user_friend" => Ok("rust_post_del_friend:5548"),
        _ => Err("address not found"),
    }
}

pub fn handle_request(request: &str) -> (String, serde_json::Value) {
    match get_address(request) {
        Ok(address) => match check_access(address) {
            true => {
                let mut stream_2_output = match TcpStream::connect(address) {
                    Ok(stream) => stream,
                    Err(e) => {
                        println!("Error: {}", e);
                        panic!();
                    }
                };

                let buffer = request.to_string();
                stream_2_output.write_all(buffer.as_bytes()).unwrap();

                let mut answer = "".to_string();
                let buffer: [u8; 1024] = [0; 1024];

                let size = stream_2_output.read_to_string(&mut answer).unwrap();
                answer.push_str(String::from_utf8_lossy(&buffer[..size]).as_ref());

                let status_line_and_content: Vec<_> = answer.split("//").collect();

                (
                        status_line_and_content[0].to_string(),
                        serde_json::from_str::<Value>(
                            status_line_and_content
                                .last()
                                .unwrap_or(&"Having trouble retrieving content from the response")
                                .trim_end_matches('\0'),
                        )
                        .unwrap_or(
                            json!({ "Error": "Having trouble getting the last value from the content" }),
                        ),
                    )
            }
            false => {
                // let response: serde_json::Value = json!({ "Error": "error" });
                (NOT_FOUND_RESPONSE.to_string(), json!({ "Error": "error" }))
            }
        },
        Err(error) => {
            let response: serde_json::Value = json!({ "Error": error });
            (NOT_FOUND_RESPONSE.to_string(), response)
        }
    }
}
