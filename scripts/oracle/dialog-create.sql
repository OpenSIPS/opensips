INSERT INTO version (table_name, table_version) values ('dialog','11');
CREATE TABLE dialog (
    dlg_id BIGINT(10) PRIMARY KEY,
    callid VARCHAR2(255),
    from_uri VARCHAR2(255),
    from_tag VARCHAR2(64),
    to_uri VARCHAR2(255),
    to_tag VARCHAR2(64),
    mangled_from_uri VARCHAR2(64) DEFAULT NULL,
    mangled_to_uri VARCHAR2(64) DEFAULT NULL,
    caller_cseq VARCHAR2(11),
    callee_cseq VARCHAR2(11),
    caller_ping_cseq NUMBER(10),
    callee_ping_cseq NUMBER(10),
    caller_route_set CLOB(512),
    callee_route_set CLOB(512),
    caller_contact VARCHAR2(255),
    callee_contact VARCHAR2(255),
    caller_sock VARCHAR2(64),
    callee_sock VARCHAR2(64),
    state NUMBER(10),
    start_time NUMBER(10),
    timeout NUMBER(10),
    vars BLOB(4096) DEFAULT NULL,
    profiles CLOB(512) DEFAULT NULL,
    script_flags NUMBER(10) DEFAULT 0 NOT NULL,
    module_flags NUMBER(10) DEFAULT 0 NOT NULL,
    flags NUMBER(10) DEFAULT 0 NOT NULL,
    rt_on_answer VARCHAR2(64) DEFAULT NULL,
    rt_on_timeout VARCHAR2(64) DEFAULT NULL,
    rt_on_hangup VARCHAR2(64) DEFAULT NULL
);

CREATE OR REPLACE TRIGGER dialog_tr
before insert on dialog FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END dialog_tr;
/
BEGIN map2users('dialog'); END;
/
