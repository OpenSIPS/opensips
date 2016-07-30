INSERT INTO version (table_name, table_version) values ('dbaliases','2');
CREATE TABLE dbaliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    alias_username CHAR(64) DEFAULT '' NOT NULL,
    alias_domain CHAR(64) DEFAULT '' NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    CONSTRAINT dbaliases_alias_idx  UNIQUE (alias_username, alias_domain)
);

CREATE INDEX dbaliases_target_idx  ON dbaliases (username, domain);

