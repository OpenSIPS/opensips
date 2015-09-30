INSERT INTO version (table_name, table_version) values ('tls_mgm','1');
CREATE TABLE tls_mgm (
    id CHAR(64) PRIMARY KEY NOT NULL,
    address CHAR(64) NOT NULL,
    type INTEGER NOT NULL,
    method CHAR(16),
    verify_cert INTEGER,
    require_cert INTEGER,
    certificate CHAR(255),
    private_key CHAR(255),
    crl_check_all INTEGER,
    crl_dir CHAR(255),
    ca_list CHAR(255),
    ca_dir CHAR(255),
    cipher_list CHAR(255),
    dh_params CHAR(255),
    ec_curve CHAR(255)
);

