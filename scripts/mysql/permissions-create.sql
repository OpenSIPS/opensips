INSERT INTO version (table_name, table_version) values ('trusted','5');
CREATE TABLE trusted (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    src_ip CHAR(50) NOT NULL,
    proto CHAR(4) NOT NULL,
    from_pattern CHAR(64) DEFAULT NULL,
    tag CHAR(32)
) ENGINE=MyISAM;

CREATE INDEX peer_idx ON trusted (src_ip);

INSERT INTO version (table_name, table_version) values ('address','4');
CREATE TABLE address (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    grp SMALLINT(5) UNSIGNED DEFAULT 0 NOT NULL,
    ip_addr CHAR(15) NOT NULL,
    mask TINYINT DEFAULT 32 NOT NULL,
    port SMALLINT(5) UNSIGNED DEFAULT 0 NOT NULL
) ENGINE=MyISAM;

