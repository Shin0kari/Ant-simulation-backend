pub const DELETE_USER_SCRIPT: &str = r#"
DELETE FROM public.users
	WHERE id_user = $1;
"#;

pub const DELETE_USER_INFO_SCRIPT: &str = r#"
DELETE FROM public.user_info
	WHERE id_user = $1;
"#;

pub const DELETE_FRIEND_LIST_SCRIPT: &str = r#"	
DELETE FROM public.friend_list
	WHERE id_user = $1;
"#;

pub const DELETE_FRIEND_SCRIPT: &str = r#"	
DELETE FROM public.friend_list
	WHERE friend_id = $1 AND id_user = $2;
"#;

pub const DELETE_USER_FROM_FRIEND_LISTS_SCRIPT: &str = r#"	
DELETE FROM public.friend_list
	WHERE friend_id = $1;
"#;

pub const DELETE_USER_ACH_SCRIPT: &str = r#"
DELETE FROM public.achievments_user
	WHERE id_user = $1;
"#;

pub const DELETE_USER_DATA_SCRIPT: &str = r#"
DELETE FROM public.user_info
	WHERE id_user = $1;

DELETE FROM public.achievments_user
	WHERE id_user = $1;

DELETE FROM public.friend_list
	WHERE id_user = $1;

DELETE FROM public.users
	WHERE id_user = $1;
"#;
