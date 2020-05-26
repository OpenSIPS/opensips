INSERT INTO version (table_name, table_version) values ('jwt_profiles','1');
CREATE TABLE jwt_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    tag CHAR(128) NOT NULL,
    sip_username CHAR(128) NOT NULL,
    CONSTRAINT jwt_profiles_jwt_tag_idx  UNIQUE (tag)
);

INSERT INTO version (table_name, table_version) values ('jwt_secrets','1');
CREATE TABLE jwt_secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    corresponding_tag CHAR(128) NOT NULL,
    secret TEXT NOT NULL,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER NOT NULL
);

