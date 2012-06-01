INSERT INTO version (table_name, table_version) values ('rtpproxy_sockets','0');
CREATE TABLE rtpproxy_sockets (
    id NUMBER(10) PRIMARY KEY,
    rtpproxy_sock CLOB,
    set_id NUMBER(10)
);

CREATE OR REPLACE TRIGGER rtpproxy_sockets_tr
before insert on rtpproxy_sockets FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END rtpproxy_sockets_tr;
/
BEGIN map2users('rtpproxy_sockets'); END;
/
