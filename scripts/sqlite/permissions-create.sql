INSERT INTO version (table_name, table_version) values ('address','5');
CREATE TABLE address (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    grp SMALLINT(5) DEFAULT 0 NOT NULL,
    ip CHAR(50) NOT NULL,
    mask TINYINT DEFAULT 32 NOT NULL,
    port SMALLINT(5) DEFAULT 0 NOT NULL,
    proto CHAR(4) DEFAULT 'any' NOT NULL,
    pattern CHAR(64) DEFAULT NULL,
    context_info CHAR(32) DEFAULT NULL
);

