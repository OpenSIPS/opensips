INSERT INTO version (table_name, table_version) values ('config','1');
CREATE TABLE config (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    name CHAR(255) NOT NULL,
    value TEXT(4096) DEFAULT NULL,
    description CHAR(255) DEFAULT NULL,
    CONSTRAINT config_name_idx  UNIQUE (name)
);

