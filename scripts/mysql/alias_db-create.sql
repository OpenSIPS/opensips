INSERT INTO version (table_name, table_version) values ('dbaliases','2');
CREATE TABLE dbaliases (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    alias_username CHAR(64) DEFAULT '' NOT NULL,
    alias_domain CHAR(64) DEFAULT '' NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    CONSTRAINT alias_idx UNIQUE (alias_username, alias_domain)
) ENGINE=InnoDB;

CREATE INDEX target_idx ON dbaliases (username, domain);

