INSERT INTO version (table_name, table_version) values ('tls_mgm','1');
CREATE TABLE tls_mgm (
    id VARCHAR2(64) PRIMARY KEY,
    address VARCHAR2(64),
    type NUMBER(10),
    method VARCHAR2(16),
    verify_cert NUMBER(10),
    require_cert NUMBER(10),
    certificate VARCHAR2(255),
    private_key VARCHAR2(255),
    crl_check_all NUMBER(10),
    crl_dir VARCHAR2(255),
    ca_list VARCHAR2(255),
    ca_dir VARCHAR2(255),
    cipher_list VARCHAR2(255),
    dh_params VARCHAR2(255),
    ec_curve VARCHAR2(255)
);

CREATE OR REPLACE TRIGGER tls_mgm_tr
before insert on tls_mgm FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END tls_mgm_tr;
/
BEGIN map2users('tls_mgm'); END;
/
