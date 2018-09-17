INSERT INTO version (table_name, table_version) values ('presentity','5');
CREATE TABLE presentity (
    id NUMBER(10) PRIMARY KEY,
    username VARCHAR2(64),
    domain VARCHAR2(64),
    event VARCHAR2(64),
    etag VARCHAR2(64),
    expires NUMBER(10),
    received_time NUMBER(10),
    body BLOB DEFAULT NULL,
    extra_hdrs BLOB DEFAULT NULL,
    sender VARCHAR2(255) DEFAULT NULL,
    CONSTRAINT presentity_presentity_idx  UNIQUE (username, domain, event, etag)
);

CREATE OR REPLACE TRIGGER presentity_tr
before insert on presentity FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END presentity_tr;
/
BEGIN map2users('presentity'); END;
/
INSERT INTO version (table_name, table_version) values ('active_watchers','12');
CREATE TABLE active_watchers (
    id NUMBER(10) PRIMARY KEY,
    presentity_uri VARCHAR2(255),
    watcher_username VARCHAR2(64),
    watcher_domain VARCHAR2(64),
    to_user VARCHAR2(64),
    to_domain VARCHAR2(64),
    event VARCHAR2(64) DEFAULT 'presence',
    event_id VARCHAR2(64),
    to_tag VARCHAR2(64),
    from_tag VARCHAR2(64),
    callid VARCHAR2(64),
    local_cseq NUMBER(10),
    remote_cseq NUMBER(10),
    contact VARCHAR2(255),
    record_route CLOB,
    expires NUMBER(10),
    status NUMBER(10) DEFAULT 2 NOT NULL,
    reason VARCHAR2(64),
    version NUMBER(10) DEFAULT 0 NOT NULL,
    socket_info VARCHAR2(64),
    local_contact VARCHAR2(255),
    sharing_tag VARCHAR2(32) DEFAULT NULL,
    CONSTRAINT ORA_active_watchers_idx  UNIQUE (presentity_uri, callid, to_tag, from_tag)
);

CREATE OR REPLACE TRIGGER active_watchers_tr
before insert on active_watchers FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END active_watchers_tr;
/
BEGIN map2users('active_watchers'); END;
/
INSERT INTO version (table_name, table_version) values ('watchers','4');
CREATE TABLE watchers (
    id NUMBER(10) PRIMARY KEY,
    presentity_uri VARCHAR2(255),
    watcher_username VARCHAR2(64),
    watcher_domain VARCHAR2(64),
    event VARCHAR2(64) DEFAULT 'presence',
    status NUMBER(10),
    reason VARCHAR2(64),
    inserted_time NUMBER(10),
    CONSTRAINT watchers_watcher_idx  UNIQUE (presentity_uri, watcher_username, watcher_domain, event)
);

CREATE OR REPLACE TRIGGER watchers_tr
before insert on watchers FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END watchers_tr;
/
BEGIN map2users('watchers'); END;
/
INSERT INTO version (table_name, table_version) values ('xcap','4');
CREATE TABLE xcap (
    id NUMBER(10) PRIMARY KEY,
    username VARCHAR2(64),
    domain VARCHAR2(64),
    doc BLOB,
    doc_type NUMBER(10),
    etag VARCHAR2(64),
    source NUMBER(10),
    doc_uri VARCHAR2(255),
    port NUMBER(10),
    CONSTRAINT xcap_account_doc_type_idx  UNIQUE (username, domain, doc_type, doc_uri)
);

CREATE OR REPLACE TRIGGER xcap_tr
before insert on xcap FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END xcap_tr;
/
BEGIN map2users('xcap'); END;
/
CREATE INDEX xcap_source_idx  ON xcap (source);

INSERT INTO version (table_name, table_version) values ('pua','8');
CREATE TABLE pua (
    id NUMBER(10) PRIMARY KEY,
    pres_uri VARCHAR2(255),
    pres_id VARCHAR2(255),
    event NUMBER(10),
    expires NUMBER(10),
    desired_expires NUMBER(10),
    flag NUMBER(10),
    etag VARCHAR2(64),
    tuple_id VARCHAR2(64),
    watcher_uri VARCHAR2(255),
    to_uri VARCHAR2(255),
    call_id VARCHAR2(64),
    to_tag VARCHAR2(64),
    from_tag VARCHAR2(64),
    cseq NUMBER(10),
    record_route CLOB,
    contact VARCHAR2(255),
    remote_contact VARCHAR2(255),
    version NUMBER(10),
    extra_headers CLOB
);

CREATE OR REPLACE TRIGGER pua_tr
before insert on pua FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END pua_tr;
/
BEGIN map2users('pua'); END;
/
CREATE INDEX pua_del1_idx  ON pua (pres_uri, event);
CREATE INDEX pua_del2_idx  ON pua (expires);
CREATE INDEX pua_update_idx  ON pua (pres_uri, pres_id, flag, event);

