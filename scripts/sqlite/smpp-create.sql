INSERT INTO version (table_name, table_version) values ('smpp','1');
CREATE TABLE smpp (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    name CHAR(255) NOT NULL,
    ip CHAR(50) NOT NULL,
    port INTEGER NOT NULL,
    system_id CHAR(16) NOT NULL,
    password CHAR(9) NOT NULL,
    system_type CHAR(13) NOT NULL,
    src_ton INTEGER NOT NULL,
    src_npi INTEGER NOT NULL,
    dst_ton INTEGER NOT NULL,
    dst_npi INTEGER NOT NULL,
    session_type INTEGER NOT NULL
);

