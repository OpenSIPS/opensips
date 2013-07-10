INSERT INTO version (table_name, table_version) values ('cachedb','1');
CREATE TABLE cachedb (
    keyname VARCHAR(255) PRIMARY KEY NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    expires INT UNSIGNED NOT NULL DEFAULT 0,
) ENGINE=MyISAM;

