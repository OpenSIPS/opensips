INSERT INTO version (table_name, table_version) values ('sip_trace','5');
CREATE TABLE sip_trace (
    id NUMBER(10) PRIMARY KEY,
    time_stamp DATE DEFAULT to_date('1900-01-01 00:00:01','yyyy-mm-dd hh24:mi:ss'),
    callid VARCHAR2(255) DEFAULT '',
    trace_attrs VARCHAR2(255) DEFAULT NULL,
    msg CLOB,
    method VARCHAR2(32) DEFAULT '',
    status VARCHAR2(255) DEFAULT NULL,
    from_proto VARCHAR2(5),
    from_ip VARCHAR2(50) DEFAULT '',
    from_port NUMBER(10),
    to_proto VARCHAR2(5),
    to_ip VARCHAR2(50) DEFAULT '',
    to_port NUMBER(10),
    fromtag VARCHAR2(64) DEFAULT '',
    direction VARCHAR2(4) DEFAULT ''
);

CREATE OR REPLACE TRIGGER sip_trace_tr
before insert on sip_trace FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END sip_trace_tr;
/
BEGIN map2users('sip_trace'); END;
/
CREATE INDEX sip_trace_trace_attrs_idx  ON sip_trace (trace_attrs);
CREATE INDEX sip_trace_date_idx  ON sip_trace (time_stamp);
CREATE INDEX sip_trace_fromip_idx  ON sip_trace (from_ip);
CREATE INDEX sip_trace_callid_idx  ON sip_trace (callid);

