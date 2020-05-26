INSERT INTO version (table_name, table_version) values ('jwt_profiles','1');
CREATE TABLE jwt_profiles (
    id SERIAL PRIMARY KEY NOT NULL,
    tag VARCHAR(128) NOT NULL,
    sip_username VARCHAR(128) NOT NULL,
    CONSTRAINT jwt_profiles_jwt_tag_idx UNIQUE (tag)
);

ALTER SEQUENCE jwt_profiles_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('jwt_secrets','1');
CREATE TABLE jwt_secrets (
    id SERIAL PRIMARY KEY NOT NULL,
    corresponding_tag VARCHAR(128) NOT NULL,
    secret TEXT NOT NULL,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER NOT NULL
);

ALTER SEQUENCE jwt_secrets_id_seq MAXVALUE 2147483647 CYCLE;
