INSERT INTO version (table_name, table_version) values ('domain','4');
CREATE TABLE domain (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    attrs CHAR(255) DEFAULT NULL,
    accept_subdomain INTEGER DEFAULT 0 NOT NULL,
    last_modified DATETIME DEFAULT '1900-01-01 00:00:01' NOT NULL,
    CONSTRAINT domain_domain_idx  UNIQUE (domain)
);

