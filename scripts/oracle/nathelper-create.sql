INSERT INTO version (table_name, table_version) values ('nh_sockets','0');
CREATE TABLE nh_sockets (
    id NUMBER(10) PRIMARY KEY,
    rtpproxy_sock CLOB,
    set_id NUMBER(10)
);

CREATE OR REPLACE TRIGGER nh_sockets_tr
before insert on nh_sockets FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END nh_sockets_tr;
/
BEGIN map2users('nh_sockets'); END;
/
