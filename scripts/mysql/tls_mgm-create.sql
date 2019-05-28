INSERT INTO version (table_name, table_version) values ('tls_mgm','3');
CREATE TABLE tls_mgm (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    domain CHAR(64) NOT NULL,
    match_ip_address CHAR(255) DEFAULT NULL,
    match_sip_domain CHAR(255) DEFAULT NULL,
    type INT(1) DEFAULT 1 NOT NULL,
    method CHAR(16) DEFAULT 'SSLv23',
    verify_cert INT(1) DEFAULT 1,
    require_cert INT(1) DEFAULT 1,
    certificate BLOB,
    private_key BLOB,
    crl_check_all INT(1) DEFAULT 0,
    crl_dir CHAR(255) DEFAULT NULL,
    ca_list MEDIUMBLOB DEFAULT NULL,
    ca_dir CHAR(255) DEFAULT NULL,
    cipher_list CHAR(255) DEFAULT NULL,
    dh_params BLOB DEFAULT NULL,
    ec_curve CHAR(255) DEFAULT NULL,
    CONSTRAINT domain_type_idx UNIQUE (domain, type)
) ENGINE=InnoDB;

