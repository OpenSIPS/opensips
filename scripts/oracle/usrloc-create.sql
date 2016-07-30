INSERT INTO version (table_name, table_version) values ('location','1011');
CREATE TABLE location (
    contact_id BIGINT(10) PRIMARY KEY,
    username VARCHAR2(64) DEFAULT '',
    domain VARCHAR2(64) DEFAULT NULL,
    contact VARCHAR2(255) DEFAULT '',
    received VARCHAR2(128) DEFAULT NULL,
    path VARCHAR2(255) DEFAULT NULL,
    expires DATE DEFAULT to_date('2020-05-28 21:32:15','yyyy-mm-dd hh24:mi:ss'),
    q NUMBER(10,2) DEFAULT 1.0 NOT NULL,
    callid VARCHAR2(255) DEFAULT 'Default-Call-ID',
    cseq NUMBER(10) DEFAULT 13 NOT NULL,
    last_modified DATE DEFAULT to_date('1900-01-01 00:00:01','yyyy-mm-dd hh24:mi:ss'),
    flags NUMBER(10) DEFAULT 0 NOT NULL,
    cflags VARCHAR2(255) DEFAULT NULL,
    user_agent VARCHAR2(255) DEFAULT '',
    socket VARCHAR2(64) DEFAULT NULL,
    methods NUMBER(10) DEFAULT NULL,
    sip_instance VARCHAR2(255) DEFAULT NULL,
    attr VARCHAR2(255) DEFAULT NULL,
    CONSTRAINT location_account_contact_idx  UNIQUE (username, domain, contact, callid)
);

CREATE OR REPLACE TRIGGER location_tr
before insert on location FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END location_tr;
/
BEGIN map2users('location'); END;
/
