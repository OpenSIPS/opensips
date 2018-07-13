INSERT INTO version (table_name, table_version) values ('tls_mgm','3');
CREATE TABLE tls_mgm (
    id NUMBER(10) PRIMARY KEY,
    domain VARCHAR2(64),
    match_ip_address VARCHAR2(255) DEFAULT NULL,
    match_sip_domain VARCHAR2(255) DEFAULT NULL,
    type NUMBER(10) DEFAULT 1 NOT NULL,
    method VARCHAR2(16) DEFAULT 'SSLv23',
    verify_cert NUMBER(10) DEFAULT 1,
    require_cert NUMBER(10) DEFAULT 1,
    certificate BLOB,
    private_key BLOB,
    crl_check_all NUMBER(10) DEFAULT 0,
    crl_dir VARCHAR2(255) DEFAULT NULL,
    ca_list BLOB DEFAULT NULL,
    ca_dir VARCHAR2(255) DEFAULT NULL,
    cipher_list VARCHAR2(255) DEFAULT NULL,
    dh_params BLOB DEFAULT NULL,
    ec_curve VARCHAR2(255) DEFAULT NULL,
    CONSTRAINT tls_mgm_domain_type_idx  UNIQUE (domain, type)
);

CREATE OR REPLACE TRIGGER tls_mgm_tr
before insert on tls_mgm FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END tls_mgm_tr;
/
BEGIN map2users('tls_mgm'); END;
/
