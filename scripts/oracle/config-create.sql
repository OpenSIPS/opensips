INSERT INTO version (table_name, table_version) values ('config','1');
CREATE TABLE config (
    id NUMBER(10) PRIMARY KEY,
    name VARCHAR2(255),
    value CLOB(4096) DEFAULT NULL,
    description VARCHAR2(255) DEFAULT NULL,
    CONSTRAINT config_name_idx  UNIQUE (name)
);

CREATE OR REPLACE TRIGGER config_tr
before insert on config FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END config_tr;
/
BEGIN map2users('config'); END;
/
