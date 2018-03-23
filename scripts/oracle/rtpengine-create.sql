INSERT INTO version (table_name, table_version) values ('rtpengine','1');
CREATE TABLE rtpengine (
    id NUMBER(10) PRIMARY KEY,
    socket CLOB,
    set_id NUMBER(10)
);

CREATE OR REPLACE TRIGGER rtpengine_tr
before insert on rtpengine FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END rtpengine_tr;
/
BEGIN map2users('rtpengine'); END;
/
