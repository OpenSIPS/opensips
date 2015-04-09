INSERT INTO version (table_name, table_version) values ('cpl','2');
CREATE TABLE cpl (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username CHAR(64) NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    cpl_xml TEXT,
    cpl_bin TEXT,
    CONSTRAINT cpl_account_idx  UNIQUE (username, domain)
);

