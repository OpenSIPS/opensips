INSERT INTO version (table_name, table_version) values ('subscriber','7');
CREATE TABLE subscriber (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    password CHAR(25) DEFAULT '' NOT NULL,
    email_address CHAR(64) DEFAULT '' NOT NULL,
    ha1 CHAR(64) DEFAULT '' NOT NULL,
    ha1b CHAR(64) DEFAULT '' NOT NULL,
    rpid CHAR(64) DEFAULT NULL,
    CONSTRAINT subscriber_account_idx  UNIQUE (username, domain)
);

CREATE INDEX subscriber_username_idx  ON subscriber (username);

