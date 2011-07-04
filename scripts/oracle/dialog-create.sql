INSERT INTO version (table_name, table_version) values ('dialog','7');
CREATE TABLE dialog (
    id NUMBER(10) PRIMARY KEY,
    hash_entry NUMBER(10),
    hash_id NUMBER(10),
    callid VARCHAR2(255),
    from_uri VARCHAR2(128),
    from_tag VARCHAR2(64),
    to_uri VARCHAR2(128),
    to_tag VARCHAR2(64),
    mangled_from_uri VARCHAR2(64) DEFAULT NULL,
    mangled_to_uri VARCHAR2(64) DEFAULT NULL,
    caller_cseq VARCHAR2(11),
    callee_cseq VARCHAR2(11),
    caller_ping_cseq NUMBER(10),
    callee_ping_cseq NUMBER(10),
    caller_route_set CLOB(512),
    callee_route_set CLOB(512),
    caller_contact VARCHAR2(128),
    callee_contact VARCHAR2(128),
    caller_sock VARCHAR2(64),
    callee_sock VARCHAR2(64),
    state NUMBER(10),
    start_time NUMBER(10),
    timeout NUMBER(10),
    vars CLOB(512) DEFAULT NULL,
    profiles CLOB(512) DEFAULT NULL,
    script_flags NUMBER(10) DEFAULT 0 NOT NULL,
    flags NUMBER(10) DEFAULT 0 NOT NULL
);

CREATE OR REPLACE TRIGGER dialog_tr
before insert on dialog FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END dialog_tr;
/
BEGIN map2users('dialog'); END;
/
CREATE INDEX dialog_hash_idx  ON dialog (hash_entry, hash_id);

