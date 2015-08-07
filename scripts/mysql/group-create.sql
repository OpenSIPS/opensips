INSERT INTO version (table_name, table_version) values ('grp','3');
CREATE TABLE grp (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    grp CHAR(64) DEFAULT '' NOT NULL,
    last_modified DATETIME DEFAULT '1900-01-01 00:00:01' NOT NULL,
    CONSTRAINT account_group_idx UNIQUE (username, domain, grp)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('re_grp','2');
CREATE TABLE re_grp (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    reg_exp CHAR(128) DEFAULT '' NOT NULL,
    group_id INT(11) DEFAULT 0 NOT NULL
) ENGINE=InnoDB;

CREATE INDEX group_idx ON re_grp (group_id);

