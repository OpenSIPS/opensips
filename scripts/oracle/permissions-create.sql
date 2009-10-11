INSERT INTO version (table_name, table_version) values ('address','5');
CREATE TABLE address (
    id NUMBER(10) PRIMARY KEY,
    grp NUMBER(5) DEFAULT 0 NOT NULL,
    ip VARCHAR2(50),
    mask NUMBER(5) DEFAULT 32 NOT NULL,
    port NUMBER(5) DEFAULT 0 NOT NULL,
    proto VARCHAR2(4) DEFAULT 'any',
    pattern VARCHAR2(64) DEFAULT NULL,
    context_info VARCHAR2(32) DEFAULT NULL
);

CREATE OR REPLACE TRIGGER address_tr
before insert on address FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END address_tr;
/
BEGIN map2users('address'); END;
/
