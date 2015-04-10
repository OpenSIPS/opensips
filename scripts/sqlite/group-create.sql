INSERT INTO version (table_name, table_version) values ('grp','3');
CREATE TABLE grp (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    grp CHAR(64) DEFAULT '' NOT NULL,
    last_modified DATETIME DEFAULT '1900-01-01 00:00:01' NOT NULL,
    CONSTRAINT grp_account_group_idx  UNIQUE (username, domain, grp)
);

INSERT INTO version (table_name, table_version) values ('re_grp','2');
CREATE TABLE re_grp (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    reg_exp CHAR(128) DEFAULT '' NOT NULL,
    group_id INTEGER DEFAULT 0 NOT NULL
);

CREATE INDEX re_grp_group_idx  ON re_grp (group_id);

