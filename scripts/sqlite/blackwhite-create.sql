INSERT INTO version (table_name, table_version) values ('blackwhite','1');
CREATE TABLE blackwhite (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username CHAR(64) DEFAULT 0 NOT NULL,
    ip CHAR(50) NOT NULL,
    mask TINYINT DEFAULT 32 NOT NULL,
    flag SMALLINT(1) DEFAULT 0 NOT NULL
);

