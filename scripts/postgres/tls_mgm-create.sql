INSERT INTO version (table_name, table_version) values ('tls_mgm','3');
CREATE TABLE tls_mgm (
    id SERIAL PRIMARY KEY NOT NULL,
    domain VARCHAR(64) NOT NULL,
    match_ip_address VARCHAR(255) DEFAULT NULL,
    match_sip_domain VARCHAR(255) DEFAULT NULL,
    type INTEGER DEFAULT 1 NOT NULL,
    method VARCHAR(16) DEFAULT 'SSLv23',
    verify_cert INTEGER DEFAULT 1,
    require_cert INTEGER DEFAULT 1,
    certificate BYTEA,
    private_key BYTEA,
    crl_check_all INTEGER DEFAULT 0,
    crl_dir VARCHAR(255) DEFAULT NULL,
    ca_list BYTEA DEFAULT NULL,
    ca_dir VARCHAR(255) DEFAULT NULL,
    cipher_list VARCHAR(255) DEFAULT NULL,
    dh_params BYTEA DEFAULT NULL,
    ec_curve VARCHAR(255) DEFAULT NULL,
    CONSTRAINT tls_mgm_domain_type_idx UNIQUE (domain, type)
);

ALTER SEQUENCE tls_mgm_id_seq MAXVALUE 2147483647 CYCLE;
