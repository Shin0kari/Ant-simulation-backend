pub const UPDATE_USER_SCRIPT: &str = r#"
UPDATE public.users
	SET (pswd, email) = ($2, $3)
	WHERE id_user = $1;
"#;

pub const UPDATE_USER_INFO_SCRIPT: &str = r#"
UPDATE public.user_info
	SET (nickname, training_complete) = ($2, $3)
	WHERE id_user = $1;
"#;

pub const UPDATE_ACH_USER_SCRIPT: &str = r#"
UPDATE public.achievments_user
	SET (ach_one, ach_two, ach_three, ach_four, ach_five) = ($2, $3, $4, $5, $6)
	WHERE id_user = $1;
"#;
