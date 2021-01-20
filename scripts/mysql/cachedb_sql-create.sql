INSERT INTO version (table_name, table_version) values ('cachedb','2');
CREATE TABLE cachedb (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    keyname CHAR(255) NOT NULL,
    value TEXT(512) NOT NULL,
    counter INT(10) DEFAULT 0 NOT NULL,
    expires INT(10) UNSIGNED DEFAULT 0 NOT NULL,
    CONSTRAINT cachedbsql_keyname_idx UNIQUE (keyname)
) ENGINE=InnoDB;

