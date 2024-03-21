use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize, Deserialize, Debug, Validate, Clone)]
pub struct User {
    pub id: Option<i32>,
    #[validate(required, length(min = 4))]
    pub pswd: Option<String>,
    #[validate(email)]
    pub email: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Validate, Clone)]
pub struct UserInfo {
    pub role: Option<String>,
    pub training_complete: Option<bool>,
    pub mtx_lvl: Option<i16>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserAch {
    pub ach: Option<Vec<bool>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserListFriend {
    pub frined_list: Option<Vec<i32>>,
    pub friend_email: Option<String>,
}
