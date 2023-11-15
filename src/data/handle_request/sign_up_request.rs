use crate::data::sql_scripts::{
    INSERT_ACH_USER_SCRIPT, INSERT_USER_INFO_SCRIPT, INSERT_USER_SCRIPT,
};

use super::func_used_in_req::{
    general_func::get_user_request_body,
    list_of_status_code::{INTERNAL_SERVER_ERROR, NOT_FOUND_RESPONSE, OK_RESPONSE},
    secret_fn::{PasswordForDatabase, DB_URL},
};
use postgres::{Client, NoTls};
use serde_json::json;
use validator::Validate;

// general: get_user_request_body
// not_gen: generate_hash_password

pub fn handle_sign_up_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((user, _user_info, _user_ach, _friend_list)), Ok(mut client)) => {
            match (
                client.query_one(
                    "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                    &[&user.email],
                ),
                // client.query_one(SELECT_NICKNAME_SCRIPT, &[&user.email]),
                user.clone().validate(),
                // user_info.clone().validate(),
            ) {
                (Ok(check_email), Ok(_)) => {
                    let user_email_presence: bool = check_email.get(0);
                    // let user_name_presence: bool = check_name.get(0);

                    match user_email_presence {
                        email_presence if email_presence == false => {
                            let hash_pswd = PasswordForDatabase::generate_hash_password(&user);

                            client
                                .execute(INSERT_USER_SCRIPT, &[&hash_pswd, &user.email])
                                .unwrap();
                            client
                                .execute(INSERT_USER_INFO_SCRIPT, &[&user.email])
                                .unwrap();
                            client
                                .execute(INSERT_ACH_USER_SCRIPT, &[&user.email])
                                .unwrap();

                            let response: serde_json::Value =
                                json!({ "Response": "User registered" });

                            (OK_RESPONSE.to_string(), response)
                        }
                        // email_presence
                        //     if email_presence == false =>
                        // {
                        //     let response: serde_json::Value =
                        //         json!({ "Error": "This name is already taken" });
                        //     (OK_RESPONSE.to_string(), response)
                        // }
                        // email_presence if email_presence => {
                        //     let response: serde_json::Value =
                        //         json!({ "Error": "This email is already taken" });
                        //     (OK_RESPONSE.to_string(), response)
                        // }
                        _ => {
                            let response: serde_json::Value =
                                json!({ "Error": "This email is already taken" });
                            (OK_RESPONSE.to_string(), response)
                        }
                    }
                }
                (Ok(_), Err(_)) => {
                    let response: serde_json::Value =
                        json!({ "Error": "This user email or pswd is not available" });
                    (NOT_FOUND_RESPONSE.to_string(), response)
                }
                // (Ok(_), Ok(_), Ok(_), Err(_)) => {
                //     let response: serde_json::Value =
                //         json!({ "Error": "This user nickname is not available" });
                //     (NOT_FOUND_RESPONSE.to_string(), response)
                // }
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
