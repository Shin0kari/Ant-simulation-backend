pub const INSERT_FRIEND_LIST_SCRIPT: &str = r#"
INSERT INTO public.friend_list(
	id_user, friend_id)
	VALUES ($2, $1);
"#;
