INSERT INTO version (table_name, table_version) values ('userblacklist','2');
CREATE TABLE userblacklist (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    prefix CHAR(64) DEFAULT '' NOT NULL,
    whitelist TINYINT(1) DEFAULT 0 NOT NULL
) ENGINE=InnoDB;

CREATE INDEX userblacklist_idx ON userblacklist (username, domain, prefix);

INSERT INTO version (table_name, table_version) values ('globalblacklist','2');
CREATE TABLE globalblacklist (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    prefix CHAR(64) DEFAULT '' NOT NULL,
    whitelist TINYINT(1) DEFAULT 0 NOT NULL,
    description CHAR(255) DEFAULT NULL
) ENGINE=InnoDB;

CREATE INDEX globalblacklist_idx ON globalblacklist (prefix);

