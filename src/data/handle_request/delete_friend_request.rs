use crate::data::sql_scripts::DELETE_FRIEND_SCRIPT;

use super::func_used_in_req::{
    general_func::{get_token_from_request, get_user_request_body},
    list_of_status_code::{INTERNAL_SERVER_ERROR, OK_RESPONSE},
    secret_fn::{Claims, DB_URL},
};
use postgres::{Client, NoTls};
use serde_json::json;

// general: get_user_request_body, get_token_from_request
// not_gen: verify_token

pub fn handle_delete_friend_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(&request),
        get_token_from_request(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((_user, _user_info, _user_ach, friend_list)), Ok(token), Ok(mut client)) => {
            match Claims::verify_token(token) {
                Ok(claims) => {
                    match (
                        client.query_one(
                            "SELECT users.id_user FROM users WHERE users.email = $1",
                            &[&claims.sub],
                        ),
                        client.query_one(
                            "SELECT users.id_user FROM users WHERE users.email = $1",
                            &[&friend_list.friend_email],
                        ),
                    ) {
                        (Ok(user_id), Ok(friend_id)) => {
                            let actual_id: i32 = user_id.get(0);
                            let friend_id: i32 = friend_id.get(0);
                            match client.query_one(
                                "SELECT EXISTS(SELECT friend_list.friend_id FROM friend_list WHERE id_user = $2 AND friend_id = $1)",
                                &[&friend_id, &actual_id],
                            ) {
                                Ok(check_if_friend_in_friend_list) => {
                                    let check_friend: bool = check_if_friend_in_friend_list.get(0);
                                    if check_friend {
                                        client
                                            .execute(
                                                DELETE_FRIEND_SCRIPT,
                                                &[&friend_id, &actual_id],
                                            )
                                            .unwrap();
                                        let response: serde_json::Value =
                                            json!({ "Response": "User removed from your friends list" });
                                        (OK_RESPONSE.to_string(), response)
                                    } else {
                                        let response: serde_json::Value =
                                            json!({ "Error": "There is no friend with this email in your friends list" });
                                        (OK_RESPONSE.to_string(), response)
                                    }
                                }
                                _ => {
                                    let response: serde_json::Value =
                                        json!({ "Error": "Some problem with connect to database" });
                                    (OK_RESPONSE.to_string(), response)
                                }
                            }
                        }
                        (Ok(_user_id), Err(_error)) => {
                            let response: serde_json::Value =
                                json!({ "Error": "This user has already been deleted" });
                            (OK_RESPONSE.to_string(), response)
                        }
                        (Err(_error), Ok(_friend_id)) => {
                            let response: serde_json::Value = json!({ "Error": "This user has already been removed from your friends list" });
                            (OK_RESPONSE.to_string(), response)
                        }
                        _ => {
                            let response: serde_json::Value =
                                json!({ "Error": "Some problem with connect to database" });
                            (OK_RESPONSE.to_string(), response)
                        }
                    }
                }
                _ => {
                    let response: serde_json::Value = json!({ "Error": "Token is not valid or some problem with connect to database" });
                    (OK_RESPONSE.to_string(), response)
                }
            }
        }
        (Err(error), Ok(_), Ok(_)) => error,
        _ => {
            let response: serde_json::Value = json!({ "Error": "Internal server error" });
            (INTERNAL_SERVER_ERROR.to_string(), response)
        }
    }
}
