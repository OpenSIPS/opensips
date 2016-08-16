INSERT INTO version (table_name, table_version) values ('tls_mgm','1');
CREATE TABLE tls_mgm (
    id CHAR(64) PRIMARY KEY NOT NULL,
    address CHAR(64) NOT NULL,
    type INT(1) NOT NULL,
    method CHAR(16),
    verify_cert INT(1),
    require_cert INT(1),
    certificate BLOB,
    private_key BLOB,
    crl_check_all INT(1),
    crl_dir CHAR(255),
    ca_list BLOB,
    ca_dir CHAR(255),
    cipher_list CHAR(255),
    dh_params BLOB,
    ec_curve CHAR(255)
) ENGINE=InnoDB;

