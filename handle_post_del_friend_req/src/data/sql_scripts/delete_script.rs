pub const DELETE_FRIEND_SCRIPT: &str = r#"	
DELETE FROM public.friend_list
	WHERE friend_id = $1 AND id_user = $2;
"#;
