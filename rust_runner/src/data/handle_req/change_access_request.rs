use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};

use serde_json::{json, Value};

use crate::data::handle_req::func_used_in_req::{
    list_of_status_code::{NOT_FOUND_RESPONSE, OK_RESPONSE},
    secret_fn::Claims,
};

use super::func_used_in_req::general_func::get_token_from_request;

pub fn handle_change_access(request: &str) -> (String, Value) {
    match get_token_from_request(request) {
        Ok(token) => match Claims::verify_token(token) {
            Ok(claims) => match claims.role.as_str() {
                "admin" => {
                    let module_name = "/".to_string();
                    let module_name: &str = &(module_name
                        + request
                            .split('/')
                            .nth(2)
                            .unwrap_or_default()
                            .split_whitespace()
                            .next()
                            .unwrap_or_default())[..];

                    let module_state: &str = request
                        .split('/')
                        .nth(3)
                        .unwrap_or_default()
                        .split_whitespace()
                        .next()
                        .unwrap_or_default();

                    println!("Module_name: {}, State: {}", module_name, module_state);

                    if module_name.is_empty() || module_state.is_empty() {
                        let response: serde_json::Value =
                            json!({ "Error": "Module name or state not provided" });
                        return (NOT_FOUND_RESPONSE.to_string(), response);
                    }

                    let mut file = File::open("access_check.json").expect("Файл не найден");

                    let mut data = String::new();
                    file.read_to_string(&mut data)
                        .expect("Ошибка при чтении файла");

                    let mut json: Value =
                        serde_json::from_str(&data).expect("Ошибка при парсинге JSON");

                    json[module_name]["state"] = module_state.into();

                    let new_data =
                        serde_json::to_string_pretty(&json).expect("Ошибка при сериализации JSON");

                    let mut file = OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open("access_check.json")
                        .expect("Ошибка при открытии файла для записи");

                    file.write_all(new_data.as_bytes())
                        .expect("Ошибка при записи в файл");

                    {
                        let response: serde_json::Value =
                            json!({ "Result": "The file was successfully modified" });
                        (NOT_FOUND_RESPONSE.to_string(), response)
                    }
                }
                _ => {
                    let response: serde_json::Value =
                        json!({ "Error": "you do not have sufficient access rights" });
                    (OK_RESPONSE.to_string(), response)
                }
            },
            _ => {
                let response: serde_json::Value = json!({ "Error": "Token is invalid" });
                (OK_RESPONSE.to_string(), response)
            }
        },
        _ => {
            let response: serde_json::Value = json!({ "Error": "Not found response" });
            (NOT_FOUND_RESPONSE.to_string(), response)
        }
    }
}
