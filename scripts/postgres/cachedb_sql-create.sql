INSERT INTO version (table_name, table_version) values ('cachedb','2');
CREATE TABLE cachedb (
    id SERIAL PRIMARY KEY NOT NULL,
    keyname VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,
    counter INTEGER DEFAULT 0 NOT NULL,
    expires INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT cachedb_cachedbsql_keyname_idx UNIQUE (keyname)
);

ALTER SEQUENCE cachedb_id_seq MAXVALUE 2147483647 CYCLE;
