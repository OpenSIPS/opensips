INSERT INTO version (table_name, table_version) values ('freeswitch','1');
CREATE TABLE freeswitch (
    id NUMBER(10) PRIMARY KEY,
    username VARCHAR2(64),
    password VARCHAR2(64),
    ip VARCHAR2(20),
    port NUMBER(10) DEFAULT 8021 NOT NULL,
    events_csv VARCHAR2(255)
);

CREATE OR REPLACE TRIGGER freeswitch_tr
before insert on freeswitch FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END freeswitch_tr;
/
BEGIN map2users('freeswitch'); END;
/
