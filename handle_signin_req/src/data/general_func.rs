use serde_json::{json, Value};

use super::{
    list_of_status_code::OK_RESPONSE,
    user_struct::{User, UserAch, UserInfo, UserListFriend},
};

pub fn get_user_request_body(
    request: &str,
) -> Result<(User, UserInfo, UserAch, UserListFriend), (String, Value)> {
    match serde_json::from_str(request.split("\r\n\r\n").last().unwrap_or_default()) {
        Ok(val) => {
            let data_value: Value = val;
            let user = User {
                id: Some(
                    data_value["user"]["id"]
                        .as_i64()
                        .unwrap_or_default()
                        .to_string()
                        .parse::<i32>()
                        .unwrap_or_default(),
                ),
                pswd: Some(
                    data_value["user"]["pswd"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                ),
                email: Some(
                    data_value["user"]["email"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                ),
            };

            let user_info = UserInfo {
                role: None,
                training_complete: Some(
                    data_value["user_info"]["training_complete"]
                        .as_bool()
                        .unwrap_or_default(),
                ),
                mtx_lvl: None,
            };

            let mut request_ach: Vec<bool> = Vec::new();

            if !data_value["user_ach"].clone().is_null() {
                for i in 0..data_value["user_ach"]
                    .clone()
                    .as_array()
                    .expect("Somthink wrong with ach, the programmer will cry")
                    .len()
                {
                    request_ach.push(data_value["user_ach"][i].as_bool().unwrap_or_default());
                }
            }

            let user_ach = UserAch {
                ach: Some(request_ach),
            };

            let friend_list = UserListFriend {
                frined_list: None,
                friend_email: Some(
                    data_value["friend_email"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                ),
            };

            Ok((user, user_info, user_ach, friend_list))
        }
        _ => {
            let response: serde_json::Value =
                json!({ "Error": "error occurred while processing the request" });
            Err((OK_RESPONSE.to_string(), response))
        }
    }
}
