INSERT INTO version (table_name, table_version) values ('subscriber','8');
CREATE TABLE subscriber (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    password CHAR(25) DEFAULT '' NOT NULL,
    ha1 CHAR(64) DEFAULT '' NOT NULL,
    ha1_sha256 CHAR(64) DEFAULT '' NOT NULL,
    ha1_sha512t256 CHAR(64) DEFAULT '' NOT NULL,
    CONSTRAINT subscriber_account_idx  UNIQUE (username, domain)
);

CREATE INDEX subscriber_username_idx  ON subscriber (username);

INSERT INTO version (table_name, table_version) values ('uri','2');
CREATE TABLE uri (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    uri_user CHAR(64) DEFAULT '' NOT NULL,
    last_modified DATETIME DEFAULT '1900-01-01 00:00:01' NOT NULL,
    CONSTRAINT uri_account_idx  UNIQUE (username, domain, uri_user)
);

