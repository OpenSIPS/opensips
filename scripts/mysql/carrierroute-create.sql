INSERT INTO version (table_name, table_version) values ('carrierroute','3');
CREATE TABLE carrierroute (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    carrier INT(10) UNSIGNED DEFAULT 0 NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    scan_prefix CHAR(64) DEFAULT '' NOT NULL,
    flags INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    mask INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    prob FLOAT DEFAULT 0 NOT NULL,
    strip INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    rewrite_host CHAR(255) DEFAULT '' NOT NULL,
    rewrite_prefix CHAR(64) DEFAULT '' NOT NULL,
    rewrite_suffix CHAR(64) DEFAULT '' NOT NULL,
    description CHAR(255) DEFAULT NULL
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('carrierfailureroute','2');
CREATE TABLE carrierfailureroute (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    carrier INT(10) UNSIGNED DEFAULT 0 NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    scan_prefix CHAR(64) DEFAULT '' NOT NULL,
    host_name CHAR(255) DEFAULT '' NOT NULL,
    reply_code CHAR(3) DEFAULT '' NOT NULL,
    flags INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    mask INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    next_domain CHAR(64) DEFAULT '' NOT NULL,
    description CHAR(255) DEFAULT NULL
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('route_tree','2');
CREATE TABLE route_tree (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    carrier CHAR(64) DEFAULT NULL
) ENGINE=InnoDB;

