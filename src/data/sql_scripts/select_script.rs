pub const SELECT_ROLE_SCRIPT: &str = r#"
SELECT user_info.role 
FROM user_info INNER JOIN users
ON user_info.id_user = users.id_user
WHERE users.id_user = (SELECT id_user FROM users WHERE users.email = $1);
"#;

pub const SELECT_NICKNAME_SCRIPT: &str = r#"
SELECT EXISTS(
    SELECT user_info.nickname 
    FROM user_info INNER JOIN users
    ON user_info.id_user = users.id_user
    WHERE users.id_user = (SELECT id_user FROM users WHERE users.email = $1));
"#;

pub const SELECT_USER_ACH_SCRIPT: &str = r#"
SELECT ach_one, ach_two, ach_three, ach_four, ach_five
	FROM public.achievments_user
	WHERE id_user = $1;
"#;

pub const SELECT_USER_SCRIPT: &str = r#"
SELECT id_user, pswd, email
	FROM public.users
    WHERE id_user = $1;
"#;

pub const SELECT_USER_INFO_SCRIPT: &str = r#"
SELECT nickname, role, training_complete, mtx_lvl_access
	FROM public.user_info
    WHERE id_user = $1;
"#;

pub const SELECT_FRIEND_LIST_SCRIPT: &str = r#"
SELECT friend_id
	FROM public.friend_list
	WHERE id_user = $1;
"#;
