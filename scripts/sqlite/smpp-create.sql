INSERT INTO version (table_name, table_version) values ('smpp','1');
CREATE TABLE smpp (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    name CHAR(255) NOT NULL,
    ip CHAR(50) NOT NULL,
    port INTEGER NOT NULL,
    system_id CHAR(16) NOT NULL,
    password CHAR(9) NOT NULL,
    system_type CHAR(13) DEFAULT '' NOT NULL,
    src_ton INTEGER DEFAULT 0 NOT NULL,
    src_npi INTEGER DEFAULT 0 NOT NULL,
    dst_ton INTEGER DEFAULT 0 NOT NULL,
    dst_npi INTEGER DEFAULT 0 NOT NULL,
    session_type INTEGER DEFAULT 1 NOT NULL,
    CONSTRAINT smpp_unique_name  UNIQUE (name)
);

