INSERT INTO version (table_name, table_version) values ('tcp_mgm','1');
CREATE TABLE tcp_mgm (
    id NUMBER(10) PRIMARY KEY,
    proto VARCHAR2(8) DEFAULT 'any',
    remote_addr VARCHAR2(43) DEFAULT NULL,
    remote_port NUMBER(10) DEFAULT 0 NOT NULL,
    local_addr VARCHAR2(43) DEFAULT NULL,
    local_port NUMBER(10) DEFAULT 0 NOT NULL,
    priority NUMBER(10) DEFAULT 0 NOT NULL,
    connect_timeout NUMBER(10) DEFAULT 100 NOT NULL,
    con_lifetime NUMBER(10) DEFAULT 120 NOT NULL,
    msg_read_timeout NUMBER(10) DEFAULT 4 NOT NULL,
    send_threshold NUMBER(10) DEFAULT 0 NOT NULL,
    no_new_conn NUMBER(10) DEFAULT 0 NOT NULL,
    alias_mode NUMBER(10) DEFAULT 0 NOT NULL,
    keepalive NUMBER(10) DEFAULT 1 NOT NULL,
    keepcount NUMBER(10) DEFAULT 9 NOT NULL,
    keepidle NUMBER(10) DEFAULT 7200 NOT NULL,
    keepinterval NUMBER(10) DEFAULT 75 NOT NULL
);

CREATE OR REPLACE TRIGGER tcp_mgm_tr
before insert on tcp_mgm FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END tcp_mgm_tr;
/
BEGIN map2users('tcp_mgm'); END;
/
