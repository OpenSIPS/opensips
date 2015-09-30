INSERT INTO version (table_name, table_version) values ('tls_mgm','1');
CREATE TABLE tls_mgm (
    id VARCHAR(64) PRIMARY KEY NOT NULL,
    address VARCHAR(64) NOT NULL,
    type INTEGER NOT NULL,
    method VARCHAR(16),
    verify_cert INTEGER,
    require_cert INTEGER,
    certificate VARCHAR(255),
    private_key VARCHAR(255),
    crl_check_all INTEGER,
    crl_dir VARCHAR(255),
    ca_list VARCHAR(255),
    ca_dir VARCHAR(255),
    cipher_list VARCHAR(255),
    dh_params VARCHAR(255),
    ec_curve VARCHAR(255)
);

