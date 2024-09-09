INSERT INTO version (table_name, table_version) values ('cachedb','2');
CREATE TABLE cachedb (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    keyname CHAR(255) NOT NULL,
    value TEXT(512) NOT NULL,
    counter INTEGER DEFAULT 0 NOT NULL,
    expires INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT cachedb_cachedbsql_keyname_idx  UNIQUE (keyname)
);

