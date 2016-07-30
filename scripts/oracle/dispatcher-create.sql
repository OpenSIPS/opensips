INSERT INTO version (table_name, table_version) values ('dispatcher','7');
CREATE TABLE dispatcher (
    id NUMBER(10) PRIMARY KEY,
    setid NUMBER(10) DEFAULT 0 NOT NULL,
    destination VARCHAR2(192) DEFAULT '',
    socket VARCHAR2(128) DEFAULT NULL,
    state NUMBER(10) DEFAULT 0 NOT NULL,
    weight NUMBER(10) DEFAULT 1 NOT NULL,
    priority NUMBER(10) DEFAULT 0 NOT NULL,
    attrs VARCHAR2(128) DEFAULT '',
    description VARCHAR2(64) DEFAULT ''
);

CREATE OR REPLACE TRIGGER dispatcher_tr
before insert on dispatcher FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END dispatcher_tr;
/
BEGIN map2users('dispatcher'); END;
/
