INSERT INTO version (table_name, table_version) values ('sockets','1');
CREATE TABLE sockets (
    id NUMBER(10) PRIMARY KEY,
    socket VARCHAR2(128),
    advertised VARCHAR2(128) DEFAULT NULL,
    tag VARCHAR2(128) DEFAULT NULL,
    flags VARCHAR2(128) DEFAULT NULL,
    tos VARCHAR2(32) DEFAULT NULL
);

CREATE OR REPLACE TRIGGER sockets_tr
before insert on sockets FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END sockets_tr;
/
BEGIN map2users('sockets'); END;
/
