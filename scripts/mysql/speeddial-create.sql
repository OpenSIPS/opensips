INSERT INTO version (table_name, table_version) values ('speed_dial','3');
CREATE TABLE speed_dial (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    sd_username CHAR(64) DEFAULT '' NOT NULL,
    sd_domain CHAR(64) DEFAULT '' NOT NULL,
    new_uri CHAR(128) DEFAULT '' NOT NULL,
    fname CHAR(64) DEFAULT '' NOT NULL,
    lname CHAR(64) DEFAULT '' NOT NULL,
    description CHAR(64) DEFAULT '' NOT NULL,
    CONSTRAINT speed_dial_idx UNIQUE (username, domain, sd_domain, sd_username)
) ENGINE=InnoDB;

