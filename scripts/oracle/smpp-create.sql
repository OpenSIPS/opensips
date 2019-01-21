INSERT INTO version (table_name, table_version) values ('smpp','1');
CREATE TABLE smpp (
    id NUMBER(10) PRIMARY KEY,
    name VARCHAR2(255),
    ip VARCHAR2(50),
    port NUMBER(10),
    system_id VARCHAR2(16),
    password VARCHAR2(9),
    system_type VARCHAR2(13),
    src_ton NUMBER(10),
    src_npi NUMBER(10),
    dst_ton NUMBER(10),
    dst_npi NUMBER(10),
    session_type NUMBER(10)
);

CREATE OR REPLACE TRIGGER smpp_tr
before insert on smpp FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END smpp_tr;
/
BEGIN map2users('smpp'); END;
/
