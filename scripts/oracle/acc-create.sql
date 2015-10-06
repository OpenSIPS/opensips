INSERT INTO version (table_name, table_version) values ('acc','7');
CREATE TABLE acc (
    id NUMBER(10) PRIMARY KEY,
    method VARCHAR2(16) DEFAULT '',
    from_tag VARCHAR2(64) DEFAULT '',
    to_tag VARCHAR2(64) DEFAULT '',
    callid VARCHAR2(64) DEFAULT '',
    sip_code VARCHAR2(3) DEFAULT '',
    sip_reason VARCHAR2(32) DEFAULT '',
    time DATE,
    duration NUMBER(10) DEFAULT 0 NOT NULL,
    ms_duration NUMBER(10) DEFAULT 0 NOT NULL,
    setuptime NUMBER(10) DEFAULT 0 NOT NULL,
    created DATE DEFAULT NULL
);

CREATE OR REPLACE TRIGGER acc_tr
before insert on acc FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END acc_tr;
/
BEGIN map2users('acc'); END;
/
CREATE INDEX acc_callid_idx  ON acc (callid);

INSERT INTO version (table_name, table_version) values ('missed_calls','5');
CREATE TABLE missed_calls (
    id NUMBER(10) PRIMARY KEY,
    method VARCHAR2(16) DEFAULT '',
    from_tag VARCHAR2(64) DEFAULT '',
    to_tag VARCHAR2(64) DEFAULT '',
    callid VARCHAR2(64) DEFAULT '',
    sip_code VARCHAR2(3) DEFAULT '',
    sip_reason VARCHAR2(32) DEFAULT '',
    time DATE,
    setuptime NUMBER(10) DEFAULT 0 NOT NULL,
    created DATE DEFAULT NULL
);

CREATE OR REPLACE TRIGGER missed_calls_tr
before insert on missed_calls FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END missed_calls_tr;
/
BEGIN map2users('missed_calls'); END;
/
CREATE INDEX missed_calls_callid_idx  ON missed_calls (callid);

