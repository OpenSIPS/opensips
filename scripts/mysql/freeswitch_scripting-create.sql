INSERT INTO version (table_name, table_version) values ('freeswitch','1');
CREATE TABLE freeswitch (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    username CHAR(64),
    password CHAR(64) NOT NULL,
    ip CHAR(20) NOT NULL,
    port INT(11) DEFAULT 8021 NOT NULL,
    events_csv CHAR(255)
) ENGINE=InnoDB;

