INSERT INTO version (table_name, table_version) values ('registrant','2');
CREATE TABLE registrant (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    registrar CHAR(255) DEFAULT '' NOT NULL,
    proxy CHAR(255) DEFAULT NULL,
    aor CHAR(255) DEFAULT '' NOT NULL,
    third_party_registrant CHAR(255) DEFAULT NULL,
    username CHAR(64) DEFAULT NULL,
    password CHAR(64) DEFAULT NULL,
    binding_URI CHAR(255) DEFAULT '' NOT NULL,
    binding_params CHAR(64) DEFAULT NULL,
    expiry INT(1) UNSIGNED DEFAULT NULL,
    forced_socket CHAR(64) DEFAULT NULL,
    cluster_shtag CHAR(64) DEFAULT NULL,
    CONSTRAINT aor_idx UNIQUE (aor)
) ENGINE=InnoDB;

