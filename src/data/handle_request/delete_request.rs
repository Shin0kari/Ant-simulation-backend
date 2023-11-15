use crate::data::sql_scripts::{
    DELETE_FRIEND_LIST_SCRIPT, DELETE_USER_ACH_SCRIPT, DELETE_USER_FROM_FRIEND_LISTS_SCRIPT,
    DELETE_USER_INFO_SCRIPT, DELETE_USER_SCRIPT,
};

use super::func_used_in_req::{
    general_func::{get_id_from_request, get_token_from_request},
    list_of_status_code::{INTERNAL_SERVER_ERROR, OK_RESPONSE},
    secret_fn::{Claims, DB_URL},
};
use postgres::{Client, NoTls};
use serde_json::json;

// general: get_token_from_request, get_id_from_request
// not_gen: verify_token

// delete_user

pub fn handle_delete_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_token_from_request(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok(token), Ok(mut client)) => match Claims::verify_token(token) {
            Ok(claims) => match claims.role {
                r if r == "user".to_string() => {
                    match client.query_one(
                        "SELECT users.id_user FROM users WHERE users.email = $1",
                        &[&claims.sub],
                    ) {
                        Ok(id) => {
                            let actual_id: i32 = id.get(0);
                            delete_user(client, actual_id)
                        }
                        _ => {
                            let response: serde_json::Value = json!({ "Error": "Error creating initial table or there is no user with this email" });
                            (OK_RESPONSE.to_string(), response)
                        }
                    }
                }
                r if r == "admin".to_string() => {
                    match get_id_from_request(&request).parse::<i32>() {
                        Ok(get_id) => delete_user(client, get_id),
                        _ => {
                            match client.query_one(
                                "SELECT users.id_user FROM users WHERE users.email = $1",
                                &[&claims.sub],
                            ) {
                                Ok(get_id) => {
                                    let actual_id: i32 = get_id.get(0);
                                    delete_user(client, actual_id)
                                }
                                _ => {
                                    let response: serde_json::Value =
                                        json!({ "Error": "Error creating initial table" });
                                    (OK_RESPONSE.to_string(), response)
                                }
                            }
                        }
                    }
                }
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

fn delete_user(mut client: Client, actual_id: i32) -> (String, serde_json::Value) {
    match (
        client.execute(DELETE_USER_INFO_SCRIPT, &[&actual_id]),
        client.execute(DELETE_FRIEND_LIST_SCRIPT, &[&actual_id]),
        client.execute(DELETE_USER_ACH_SCRIPT, &[&actual_id]),
        client.execute(DELETE_USER_SCRIPT, &[&actual_id]),
        client.execute(DELETE_USER_FROM_FRIEND_LISTS_SCRIPT, &[&actual_id]),
    ) {
        (
            Ok(_delete_user_info_line),
            Ok(_delete_friend_list_line),
            Ok(_delete_user_ach_line),
            Ok(_delete_user_line),
            Ok(_delete_user_from_friend_lists_line),
        ) => {
            let response: serde_json::Value = json!({ "Response": "User deleted" });
            (OK_RESPONSE.to_string(), response)
        }
        _ => {
            let response: serde_json::Value = json!({ "Error": "Error initial one of struct" });
            (OK_RESPONSE.to_string(), response)
        }
    }
}
