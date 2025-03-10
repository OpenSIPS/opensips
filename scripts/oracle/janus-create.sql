INSERT INTO version (table_name, table_version) values ('janus','1');
CREATE TABLE janus (
    id NUMBER(10) PRIMARY KEY,
    janus_id CLOB,
    janus_url CLOB
);

CREATE OR REPLACE TRIGGER janus_tr
before insert on janus FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END janus_tr;
/
BEGIN map2users('janus'); END;
/
