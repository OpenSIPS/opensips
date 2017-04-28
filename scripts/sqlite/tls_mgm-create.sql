INSERT INTO version (table_name, table_version) values ('tls_mgm','2');
CREATE TABLE tls_mgm (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    domain CHAR(64) NOT NULL,
    address CHAR(64) DEFAULT NULL,
    type INTEGER DEFAULT 1 NOT NULL,
    method CHAR(16) DEFAULT 'SSLv23',
    verify_cert INTEGER DEFAULT 1,
    require_cert INTEGER DEFAULT 1,
    certificate BLOB,
    private_key BLOB,
    crl_check_all INTEGER DEFAULT 0,
    crl_dir CHAR(255) DEFAULT NULL,
    ca_list BLOB DEFAULT NULL,
    ca_dir CHAR(255) DEFAULT NULL,
    cipher_list CHAR(255) DEFAULT NULL,
    dh_params BLOB DEFAULT NULL,
    ec_curve CHAR(255) DEFAULT NULL,
    CONSTRAINT tls_mgm_domain_type_idx  UNIQUE (domain, type)
);

