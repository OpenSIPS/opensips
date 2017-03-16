INSERT INTO version (table_name, table_version) values ('tls_mgm','2');
CREATE TABLE tls_mgm (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    domain CHAR(64) NOT NULL,
    address CHAR(64) NOT NULL,
    type INT(1) DEFAULT 1 NOT NULL,
    method CHAR(16) DEFAULT 'SSLv23',
    verify_cert INT(1) DEFAULT 0,
    require_cert INT(1) DEFAULT 0,
    certificate BLOB,
    private_key BLOB,
    crl_check_all INT(1) DEFAULT 0,
    crl_dir CHAR(255) DEFAULT NULL,
    ca_list BLOB DEFAULT NULL,
    ca_dir CHAR(255) DEFAULT NULL,
    cipher_list CHAR(255) DEFAULT NULL,
    dh_params BLOB DEFAULT NULL,
    ec_curve CHAR(255) DEFAULT NULL
) ENGINE=InnoDB;

