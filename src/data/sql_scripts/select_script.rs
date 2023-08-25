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
