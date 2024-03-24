use serde_json::Value;
use std::fs;

pub fn check_access(address: &str) -> bool {
    let check_data = match fs::read_to_string("access_check.json") {
        Ok(data_file) => data_file,
        Err(error) => {
            println!("file not found: {:?}", error);
            return false;
        }
    };

    match serde_json::from_str(&check_data) {
        Ok(val) => {
            let data_value: Value = val;
            let check = data_value[address.split(':').next().unwrap_or_default()]["state"]
                .as_str()
                .unwrap_or_default();
            matches!(check, "+")
        }
        _ => false,
    }
}

use postgres::Client;
use serde_json::json;

use postgres::Error as PostgresError;

use crate::data::sql_scripts::{
    delete_script::{
        DELETE_FRIEND_LIST_SCRIPT, DELETE_USER_ACH_SCRIPT, DELETE_USER_FROM_FRIEND_LISTS_SCRIPT,
        DELETE_USER_INFO_SCRIPT, DELETE_USER_SCRIPT,
    },
    select_script::{
        SELECT_FRIEND_LIST_SCRIPT, SELECT_USER_ACH_SCRIPT, SELECT_USER_INFO_SCRIPT,
        SELECT_USER_SCRIPT,
    },
    update_script::{UPDATE_ACH_USER_SCRIPT, UPDATE_USER_INFO_SCRIPT, UPDATE_USER_SCRIPT},
};

use super::{
    list_of_status_code::OK_RESPONSE,
    secret_fn::{Claims, PasswordForDatabase},
    user_struct::{User, UserAch, UserInfo, UserListFriend},
};

pub fn delete_user(mut client: Client, actual_id: i32) -> (String, serde_json::Value) {
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
        ) => (
            OK_RESPONSE.to_string(),
            json!({ "Response": "User deleted" }),
        ),
        _ => (
            OK_RESPONSE.to_string(),
            json!({ "Error": "Error initial one of struct" }),
        ),
    }
}

pub fn update_user(
    user: &mut User,
    user_info: &mut UserInfo,
    user_ach: UserAch,
    client: &mut Client,
    actual_id: i32,
) -> (String, serde_json::Value) {
    match select_user_data(actual_id, client) {
        Ok((db_user, db_user_info, db_user_ach, _db_user_friends)) => {
            let hash_pswd = PasswordForDatabase::generate_hash_password(user);

            let check_user_info_role = user_info.role.is_none();
            let check_user_info_mtx_lvl = user_info.mtx_lvl.is_none();
            let check_user_info_training_complete = user_info.training_complete.is_none();

            if user.email.clone().unwrap_or("".to_string()).is_empty() {
                user.email = db_user.email;
            }
            if user.pswd.clone().unwrap_or("".to_string()).is_empty() {
                user.pswd = db_user.pswd;
            }
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
                    let token = Claims::create_jwt_token(user, user_info);

                    // // для user_ach
                    let mut data_ach: Vec<bool> = Vec::new();
                    let mut update_user_ach = user_ach.ach.clone().unwrap_or_default().into_iter();

                    for actual_user_ach in db_user_ach.ach.unwrap_or_default() {
                        if actual_user_ach || update_user_ach.next().unwrap_or_default() {
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

                    (OK_RESPONSE.to_string(), json!({ "Response": token }))
                }
                (Ok(_), Err(_)) => (
                    OK_RESPONSE.to_string(),
                    json!({ "Error": "_check_update_user" }),
                ),
                (Err(_), Ok(_)) => (
                    OK_RESPONSE.to_string(),
                    json!({ "Error": "_check_update_user_info" }),
                ),
                _ => (
                    OK_RESPONSE.to_string(),
                    json!({ "Error": "Error occurred while updating the user" }),
                ),
            }
        }
        _ => (
            OK_RESPONSE.to_string(),
            json!({ "Error": "An error occurred while retrieving user data when updating user info" }),
        ),
    }
}

pub fn select_user_data(
    actual_id: i32,
    client: &mut Client,
) -> Result<(User, UserInfo, UserAch, UserListFriend), (String, serde_json::Value)> {
    match (
        get_user(actual_id, client),
        get_user_info(actual_id, client),
        get_user_ach(actual_id, client),
        get_user_friends(actual_id, client),
    ) {
        (Ok(user), Ok(user_info), Ok(user_ach), Ok(friend_list)) => {
            Ok((user, user_info, user_ach, friend_list))
        }
        _ => Err((
            OK_RESPONSE.to_string(),
            json!({ "Error": "Error creating initial table" }),
        )),
    }
}

fn get_user_friends(actual_id: i32, client: &mut Client) -> Result<UserListFriend, PostgresError> {
    match client.query(SELECT_FRIEND_LIST_SCRIPT, &[&actual_id]) {
        Ok(db_data) => {
            let mut data_id_friends: Vec<i32> = Vec::new();

            for id in db_data {
                data_id_friends.push(id.get(0));
            }

            Ok(UserListFriend {
                frined_list: Some(data_id_friends),
                friend_email: None,
            })
        }
        Err(error) => Err(error),
    }
}

fn get_user_ach(actual_id: i32, client: &mut Client) -> Result<UserAch, PostgresError> {
    match client.query_one(SELECT_USER_ACH_SCRIPT, &[&actual_id]) {
        Ok(db_data) => {
            let mut data_ach: Vec<bool> = Vec::new();

            for i in 0..db_data.len() {
                data_ach.push(db_data.get(i));
            }

            Ok(UserAch {
                ach: Some(data_ach),
            })
        }
        Err(error) => Err(error),
    }
}

fn get_user(actual_id: i32, client: &mut Client) -> Result<User, PostgresError> {
    match client.query_one(SELECT_USER_SCRIPT, &[&actual_id]) {
        Ok(db_data) => Ok(User {
            id: Some(db_data.get(0)),
            pswd: Some(db_data.get(1)),
            email: Some(db_data.get(2)),
        }),
        Err(error) => Err(error),
    }
}

fn get_user_info(actual_id: i32, client: &mut Client) -> Result<UserInfo, PostgresError> {
    match client.query_one(SELECT_USER_INFO_SCRIPT, &[&actual_id]) {
        Ok(db_data) => Ok(UserInfo {
            // name: Some(db_data.get(0)),
            role: Some(db_data.get(0)),
            training_complete: Some(db_data.get(1)),
            mtx_lvl: Some(db_data.get(2)),
        }),
        Err(error) => Err(error),
    }
}

fn get_friend_email(actual_id: i32, client: &mut Client) -> Result<String, PostgresError> {
    match client.query_one(SELECT_USER_SCRIPT, &[&actual_id]) {
        Ok(db_data) => {
            let friend_email: String = db_data.get(2);
            Ok(friend_email)
        }
        Err(error) => Err(error),
    }
}

// изменить отображение friend_id более удобное для сервера
pub fn read_user(mut client: Client, actual_id: i32, root: &str) -> (String, serde_json::Value) {
    match select_user_data(actual_id, &mut client) {
        Ok((user, user_info, user_ach, friend_list)) => {
            let mut ach_str = "".to_string();
            // no unwrap?
            for ach in user_ach.ach.unwrap().iter() {
                if *ach {
                    ach_str += "true "
                } else {
                    ach_str += "false "
                }
            }

            let mut friends_email_vec: Vec<String> = Vec::new();
            // let mut friends_id_str = "".to_string();
            for id in friend_list.frined_list.unwrap() {
                match get_friend_email(id, &mut client) {
                    Ok(data_email) => {
                        friends_email_vec.push(data_email);
                    }
                    Err(_error) => {}
                }
                // friends_id_str = friends_id_str + id.to_string().as_str() + " ";
            }

            let response: serde_json::Value = if root == "admin" {
                json!({
                    "Response": {
                        "User": {
                            "id": user.id.unwrap(),
                            "email": user.email.unwrap()
                        },
                        "User_info": {
                            // "name": user_info.name.unwrap(),
                            "role": user_info.role.unwrap(),
                            "training_complete": user_info.training_complete.unwrap(),
                            "mtx_lvl": user_info.mtx_lvl.unwrap()
                        },
                        "User_ach": {
                            "ach": ach_str,
                        },
                        "Friend_list": {
                            "friends_email": [friends_email_vec],
                        }
                    }
                })
            } else {
                json!({
                    "Response": {
                        "User": {
                            // "id": user.id.unwrap(),
                            "email": user.email.unwrap()
                        },
                        "User_info": {
                            // "name": user_info.name.unwrap(),
                            // "role": user_info.role.unwrap(),
                            "training_complete": user_info.training_complete.unwrap(),
                            "mtx_lvl": user_info.mtx_lvl.unwrap()
                        },
                        "User_ach": {
                            "ach": ach_str,
                        },
                        "Friend_list": {
                            "friends_id": [friends_email_vec],
                        }
                    }
                })
            };

            (OK_RESPONSE.to_string(), response)
        }
        _ => (
            OK_RESPONSE.to_string(),
            json!({ "Error": "Error creating initial table" }),
        ),
    }
}
