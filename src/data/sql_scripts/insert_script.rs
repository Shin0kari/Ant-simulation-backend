pub const INSERT_USER_SCRIPT: &str = r#"
INSERT INTO public.users(
	id_user, pswd, email)
	VALUES (DEFAULT, $1, $2);
"#;

pub const INSERT_USER_INFO_SCRIPT: &str = r#"
INSERT INTO public.user_info(
	id_user, nickname)
	VALUES ((SELECT id_user FROM public.users WHERE email = $1), $2);
"#;

pub const INSERT_ACH_USER_SCRIPT: &str = r#"
INSERT INTO public.achievments_user(
	id_user)
	VALUES ((SELECT id_user FROM public.users WHERE email = $1));
"#;
