pub const CREATE_DIAG: &str = r#"
CREATE TABLE IF NOT EXISTS public.users(
    id_user SERIAL PRIMARY KEY,
	pswd character varying COLLATE pg_catalog."default" NOT NULL,
    email character varying COLLATE pg_catalog."default" NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS public.user_info
(
    id_user integer NOT NULL UNIQUE,
    role character varying COLLATE pg_catalog."default" NOT NULL DEFAULT 'user'::character varying,
    training_complete boolean NOT NULL DEFAULT false,
    mtx_lvl_access smallint NOT NULL DEFAULT 1,
    CONSTRAINT user_info_pkey PRIMARY KEY (id_user),
    CONSTRAINT fk_user_info FOREIGN KEY (id_user)
        REFERENCES public.users (id_user) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
);

CREATE TABLE IF NOT EXISTS public.friend_list
(
    id_user integer NOT NULL,
    friend_id integer NOT NULL,
    CONSTRAINT fk_friend_list FOREIGN KEY (id_user)
        REFERENCES public.users (id_user) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
);

CREATE TABLE IF NOT EXISTS public.achievments_user
(
    id_user integer NOT NULL UNIQUE,
    ach_one boolean NOT NULL DEFAULT false,
    ach_two boolean NOT NULL DEFAULT false,
    ach_three boolean NOT NULL DEFAULT false,
    ach_four boolean NOT NULL DEFAULT false,
    ach_five boolean NOT NULL DEFAULT false,
    CONSTRAINT achievments_user_pkey PRIMARY KEY (id_user),
    CONSTRAINT fk_ach FOREIGN KEY (id_user)
        REFERENCES public.users (id_user) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
);
"#;
