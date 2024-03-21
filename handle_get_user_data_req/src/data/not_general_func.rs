use postgres::Client;
use serde_json::json;

use crate::sql_scripts::select_script::{
    SELECT_FRIEND_LIST_SCRIPT, SELECT_USER_ACH_SCRIPT, SELECT_USER_INFO_SCRIPT, SELECT_USER_SCRIPT,
};

use super::{
    list_of_status_code::OK_RESPONSE,
    user_struct::{User, UserAch, UserInfo, UserListFriend},
};

use postgres::Error as PostgresError;

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
        _ => {
            let response: serde_json::Value = json!({ "Error": "Error creating initial table" });
            Err((OK_RESPONSE.to_string(), response))
        }
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
        _ => {
            let response: serde_json::Value = json!({ "Error": "Error creating initial table" });
            (OK_RESPONSE.to_string(), response)
        }
    }
}
