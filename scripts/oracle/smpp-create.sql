INSERT INTO version (table_name, table_version) values ('smpp','1');
CREATE TABLE smpp (
    id NUMBER(10) PRIMARY KEY,
    name VARCHAR2(255),
    ip VARCHAR2(50),
    port NUMBER(10),
    system_id VARCHAR2(16),
    password VARCHAR2(9),
    system_type VARCHAR2(13) DEFAULT '',
    src_ton NUMBER(10) DEFAULT 0 NOT NULL,
    src_npi NUMBER(10) DEFAULT 0 NOT NULL,
    dst_ton NUMBER(10) DEFAULT 0 NOT NULL,
    dst_npi NUMBER(10) DEFAULT 0 NOT NULL,
    session_type NUMBER(10) DEFAULT 1 NOT NULL,
    CONSTRAINT smpp_unique_name  UNIQUE (name)
);

CREATE OR REPLACE TRIGGER smpp_tr
before insert on smpp FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END smpp_tr;
/
BEGIN map2users('smpp'); END;
/
