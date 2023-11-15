use crate::data::sql_scripts::{
    UPDATE_ACH_USER_SCRIPT, UPDATE_USER_INFO_SCRIPT, UPDATE_USER_SCRIPT,
};

use super::{
    func_used_in_req::{
        general_func::{get_id_from_request, get_token_from_request, get_user_request_body},
        list_of_status_code::{INTERNAL_SERVER_ERROR, OK_RESPONSE},
        secret_fn::{Claims, PasswordForDatabase, DB_URL},
        user_struct::{User, UserAch, UserInfo},
    },
    get_request::select_user_data,
};
use postgres::{Client, NoTls};
use serde_json::json;
use validator::Validate;

// general: get_user_request_body, get_token_from_request, get_id_from_request
// not_gen: select_user_data, create_jwt_token, generate_hash_password, verify_token, validate

pub fn handle_put_request(request: &str) -> (String, serde_json::Value) {
    match (
        get_user_request_body(&request),
        get_token_from_request(&request),
        Client::connect(DB_URL, NoTls),
    ) {
        (Ok((mut user, mut user_info, user_ach, _friend_list)), Ok(token), Ok(mut client)) => {
            match (
                Claims::verify_token(token),
                user.clone().validate(),
                // user_info.clone().validate(),
            ) {
                (Ok(claims), Ok(_)) => {
                    // возможно изменить на получение роли из бд
                    match claims.role {
                        r if r == "user".to_string() => {
                            user_info.role = Some(r);
                            // 2 проверка нужна, если хотим сменить email
                            match (
                                client.query_one(
                                "SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                                &[&user.email]),
                                client.query_one("SELECT users.id_user FROM users WHERE users.email = $1", &[&claims.sub]),
                            ) {
                                (Ok(check_email), Ok(id)) => {
                                    let user_email_presence: bool = check_email.get(0);
                                    let actual_id: i32 = id.get(0);

                                    if user.email != Some(claims.sub) {
                                        if user_email_presence == false {
                                            update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
                                        } else {
                                            let response: serde_json::Value =
                                                json!({ "Error": "This email is already taken" });
                                            (OK_RESPONSE.to_string(), response)
                                        }
                                    } else {
                                        update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
                                    }
                                }
                                _ => {
                                    let response: serde_json::Value =
                                        json!({ "Error": "Error creating initial table or there is no user with this id" });
                                    (OK_RESPONSE.to_string(), response)
                                }
                            }
                        }
                        r if r == "admin".to_string() => {
                            user_info.role = Some(r);
                            match get_id_from_request(&request).parse::<i32>() {
                                Ok(get_id) => {
                                    // изменяет кого-то
                                    match client.query_one("SELECT EXISTS(SELECT users.id_user FROM users WHERE users.id_user = $1)",
                                    &[&get_id]) {
                                    Ok(check_id) => {
                                        let user_id_presence: bool = check_id.get(0);

                                        if user_id_presence {
                                            // 1-ое для проверки, чтобы не поменяли на тот же email, 2-ое для получения email пользователя
                                            match (client.query_one("SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                                                &[&user.email]),
                                                client.query_one("SELECT users.email FROM users WHERE users.id_user = $1", &[&get_id]),
                                            ) {
                                                (Ok(check_email), Ok(get_email)) => {
                                                    let user_email_presence: bool = check_email.get(0);
                                                    let get_user_email: String = get_email.get(0);

                                                    match (user_email_presence, get_user_email) {
                                                        (presence_email, actual_email) if presence_email && actual_email == user.email.clone().unwrap() => {
                                                            update_user(&mut user, &mut user_info, user_ach, &mut client, get_id)
                                                        }
                                                        (presence_email, _actual_email) if presence_email == false => {
                                                            update_user(&mut user, &mut user_info, user_ach, &mut client, get_id)
                                                        }
                                                        _ => {
                                                            let response: serde_json::Value =
                                                                json!({ "Error": "This email is already taken" });
                                                            (OK_RESPONSE.to_string(), response)
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    let response: serde_json::Value =
                                                        json!({ "Error": "Error creating initial table" });
                                                    (OK_RESPONSE.to_string(), response)
                                                }
                                            }
                                        } else {
                                            let response: serde_json::Value =
                                                json!({ "Error": "There is no user with this id" });
                                            (OK_RESPONSE.to_string(), response)
                                        }
                                    }
                                    _ => {
                                        let response: serde_json::Value =
                                            json!({ "Error": "Error creating initial table" });
                                        (OK_RESPONSE.to_string(), response)
                                    }
                                }
                                }
                                _ => {
                                    match (
                                    client.query_one("SELECT EXISTS(SELECT users.email FROM users WHERE users.email = $1)",
                                    &[&user.email]),
                                    client.query_one("SELECT users.id_user FROM users WHERE users.email = $1",
                                    &[&claims.sub]),) {
                                    (Ok(check_email), Ok(get_id)) => {
                                        let user_email_presence: bool = check_email.get(0);
                                        let actual_id: i32 = get_id.get(0);
                                                // изменённый email и истинный email
                                        if user.email != Some(claims.sub) {
                                            if user_email_presence == false {
                                                update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
                                            } else {
                                                let response: serde_json::Value =
                                                    json!({ "Error": "This email is already taken" });
                                                (OK_RESPONSE.to_string(), response)
                                            }
                                        } else {
                                            update_user(&mut user, &mut user_info, user_ach, &mut client, actual_id)
                                        }
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
                    }
                }
                (Ok(_), Err(_)) => {
                    let response: serde_json::Value =
                        json!({ "Error": "This user email or password is not available" });
                    (OK_RESPONSE.to_string(), response)
                }
                // (Ok(_), Ok(_), Err(_)) => {
                //     let response: serde_json::Value =
                //         json!({ "Error": "This user nickname is not available" });
                //     (OK_RESPONSE.to_string(), response)
                // }
                _ => {
                    let response: serde_json::Value = json!({ "Error": "Token is invalid" });
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

fn update_user(
    user: &mut User,
    user_info: &mut UserInfo,
    user_ach: UserAch,
    client: &mut Client,
    actual_id: i32,
) -> (String, serde_json::Value) {
    match select_user_data(actual_id, client) {
        Ok((db_user, db_user_info, db_user_ach, _db_user_friends)) => {
            let hash_pswd = PasswordForDatabase::generate_hash_password(&user);

            let check_user_info_role = user_info.role.clone().is_none();
            let check_user_info_mtx_lvl = user_info.mtx_lvl.clone().is_none();
            let check_user_info_training_complete = user_info.training_complete.clone().is_none();

            if user.email.clone().unwrap_or("".to_string()).len() == 0 {
                user.email = db_user.email;
            }
            if user.pswd.clone().unwrap_or("".to_string()).len() == 0 {
                user.pswd = db_user.pswd;
            }
            // if user_info.name.clone().unwrap_or("".to_string()).len() == 0 {
            //     user_info.name = db_user_info.name;
            // }
            if check_user_info_role {
                user_info.role = db_user_info.role;
            }
            if check_user_info_mtx_lvl {
                user_info.mtx_lvl = db_user_info.mtx_lvl;
            }
            if check_user_info_training_complete {
                user_info.training_complete = db_user_info.training_complete;
            }

            match (
                client.execute(UPDATE_USER_SCRIPT, &[&actual_id, &hash_pswd, &user.email]),
                client.execute(
                    UPDATE_USER_INFO_SCRIPT,
                    &[&actual_id, &user_info.training_complete],
                ),
            ) {
                (Ok(_check_update_user), Ok(_check_update_user_info)) => {
                    // необходим при обновлении email и pswd пользователя
                    let token = Claims::create_jwt_token(&user, &user_info);

                    // // для user_ach
                    let mut data_ach: Vec<bool> = Vec::new();
                    let mut update_user_ach = user_ach.ach.clone().unwrap_or_default().into_iter();

                    for actual_user_ach in db_user_ach.ach.unwrap_or_default() {
                        if (actual_user_ach || update_user_ach.next().unwrap_or_default()) == true {
                            data_ach.push(true);
                        } else {
                            data_ach.push(false);
                        }
                    }

                    client
                        .execute(
                            UPDATE_ACH_USER_SCRIPT,
                            &[
                                &actual_id,
                                &data_ach[0],
                                &data_ach[1],
                                &data_ach[2],
                                &data_ach[3],
                                &data_ach[4],
                            ],
                        )
                        .unwrap();

                    let response: serde_json::Value = json!({ "Response": token });
                    (OK_RESPONSE.to_string(), response)
                }
                (Ok(_), Err(_)) => {
                    let response: serde_json::Value = json!({ "Error": "_check_update_user" });
                    (OK_RESPONSE.to_string(), response)
                }
                (Err(_), Ok(_)) => {
                    let response: serde_json::Value = json!({ "Error": "_check_update_user_info" });
                    (OK_RESPONSE.to_string(), response)
                }
                _ => {
                    let response: serde_json::Value =
                        json!({ "Error": "Error occurred while updating the user" });
                    (OK_RESPONSE.to_string(), response)
                }
            }
        }
        _ => {
            let response: serde_json::Value = json!({ "Error": "An error occurred while retrieving user data when updating user info" });
            (OK_RESPONSE.to_string(), response)
        }
    }
}
