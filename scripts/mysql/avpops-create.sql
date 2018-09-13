INSERT INTO version (table_name, table_version) values ('usr_preferences','3');
CREATE TABLE usr_preferences (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    uuid CHAR(64) DEFAULT '' NOT NULL,
    username CHAR(64) DEFAULT 0 NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    attribute CHAR(32) DEFAULT '' NOT NULL,
    type INT(11) DEFAULT 0 NOT NULL,
    value CHAR(128) DEFAULT '' NOT NULL,
    last_modified DATETIME DEFAULT '1900-01-01 00:00:01' NOT NULL
) ENGINE=InnoDB;

CREATE INDEX ua_idx ON usr_preferences (uuid, attribute);
CREATE INDEX uda_idx ON usr_preferences (username, domain, attribute);
CREATE INDEX value_idx ON usr_preferences (value);

