INSERT INTO version (table_name, table_version) values ('silo','6');
CREATE TABLE silo (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    src_addr CHAR(255) DEFAULT '' NOT NULL,
    dst_addr CHAR(255) DEFAULT '' NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    inc_time INTEGER DEFAULT 0 NOT NULL,
    exp_time INTEGER DEFAULT 0 NOT NULL,
    snd_time INTEGER DEFAULT 0 NOT NULL,
    ctype CHAR(255) DEFAULT NULL,
    body BLOB DEFAULT NULL
);

CREATE INDEX silo_account_idx  ON silo (username, domain);

