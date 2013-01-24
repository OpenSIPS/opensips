INSERT INTO version (table_name, table_version) values ('cachedb','1');
CREATE TABLE cachedb (
    keyname VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,
    counter INTEGER DEFAULT 0 NOT NULL,
    expires INTEGER DEFAULT 0 NOT NULL
);

