INSERT INTO version (table_name, table_version) values ('smpp','1');
CREATE TABLE smpp (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    name CHAR(255) NOT NULL,
    ip CHAR(50) NOT NULL,
    port INT(5) UNSIGNED NOT NULL,
    system_id CHAR(16) NOT NULL,
    password CHAR(9) NOT NULL,
    system_type CHAR(13) DEFAULT '' NOT NULL,
    src_ton INT UNSIGNED DEFAULT 0 NOT NULL,
    src_npi INT UNSIGNED DEFAULT 0 NOT NULL,
    dst_ton INT UNSIGNED DEFAULT 0 NOT NULL,
    dst_npi INT UNSIGNED DEFAULT 0 NOT NULL,
    session_type INT UNSIGNED DEFAULT 1 NOT NULL,
    CONSTRAINT unique_name UNIQUE (name)
) ENGINE=InnoDB;

