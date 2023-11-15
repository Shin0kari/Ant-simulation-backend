use crate::data::sql_scripts::SELECT_ROLE_SCRIPT;

use super::func_used_in_req::{
    general_func::get_user_request_body,
    list_of_status_code::{INTERNAL_SERVER_ERROR, NOT_FOUND_RESPONSE, OK_RESPONSE},
    secret_fn::{Claims, PasswordForDatabase, DB_URL},
};
use postgres::{Client, NoTls};
use serde_json::json;

// general: get_user_request_body
// not_gen: verify_password

pub fn handle_sign_in_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
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
                                    let response: serde_json::Value = json!({ "Response": token });
                                    (OK_RESPONSE.to_string(), response)
                                } else {
                                    let response: serde_json::Value =
                                        json!({ "Error": "Wrong email or password" });
                                    (OK_RESPONSE.to_string(), response)
                                }
                            }
                            _ => {
                                let response: serde_json::Value =
                                    json!({ "Error": "Trouble getting role" });
                                (
                                    NOT_FOUND_RESPONSE.to_string(), // изменить на другу ошибку
                                    response,
                                )
                            }
                        }
                    } else {
                        let response: serde_json::Value =
                            json!({ "Error": "There is no user with this email" });
                        (
                            NOT_FOUND_RESPONSE.to_string(), // изменить на другу ошибку
                            response,
                        )
                    }
                }
                _ => {
                    let response: serde_json::Value =
                        json!({ "Error": "Error creating initial table" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
            }
        }
        (Err(error), Ok(_)) => error,
        _ => {
            let response: serde_json::Value = json!({ "Error": "Internal server error" });
            (INTERNAL_SERVER_ERROR.to_string(), response)
        }
    }
}
