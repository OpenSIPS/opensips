INSERT INTO version (table_name, table_version) values ('blackwhite','1');

CREATE TABLE blackwhite (
    id NUMBER(10) PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    ip VARCHAR(50) NOT NULL,
    mask NUMBER(2) DEFAULT 32 NOT NULL,
    flag NUMBER(1) DEFAULT 0 NOT NULL
);

CREATE OR REPLACE TRIGGER blackwhite_tr
before insert on blackwhite FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END blackwhite_tr;
/
BEGIN map2users('blackwhite'); END;
/
