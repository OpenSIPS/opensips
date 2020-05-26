INSERT INTO version (table_name, table_version) values ('jwt_profiles','1');
CREATE TABLE jwt_profiles (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    tag CHAR(128) NOT NULL,
    sip_username CHAR(128) NOT NULL,
    CONSTRAINT jwt_tag_idx UNIQUE (tag)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('jwt_secrets','1');
CREATE TABLE jwt_secrets (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    corresponding_tag CHAR(128) NOT NULL,
    secret TEXT NOT NULL,
    start_ts INT NOT NULL,
    end_ts INT NOT NULL
) ENGINE=InnoDB;

