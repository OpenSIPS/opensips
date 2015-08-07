INSERT INTO version (table_name, table_version) values ('cachedb','2');
CREATE TABLE cachedb (
    keyname CHAR(255) PRIMARY KEY NOT NULL,
    value TEXT(512) NOT NULL,
    counter INT(10) DEFAULT 0 NOT NULL,
    expires INT(10) UNSIGNED DEFAULT 0 NOT NULL
) ENGINE=InnoDB;

