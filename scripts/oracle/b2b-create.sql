INSERT INTO version (table_name, table_version) values ('b2b_entities','2');
CREATE TABLE b2b_entities (
    id NUMBER(10) PRIMARY KEY,
    type NUMBER(10),
    state NUMBER(10),
    ruri VARCHAR2(255),
    from_uri VARCHAR2(255),
    to_uri VARCHAR2(255),
    from_dname VARCHAR2(64),
    to_dname VARCHAR2(64),
    tag0 VARCHAR2(64),
    tag1 VARCHAR2(64),
    callid VARCHAR2(64),
    cseq0 NUMBER(10),
    cseq1 NUMBER(10),
    contact0 VARCHAR2(255),
    contact1 VARCHAR2(255),
    route0 CLOB,
    route1 CLOB,
    sockinfo_srv VARCHAR2(64),
    param VARCHAR2(255),
    mod_name VARCHAR2(32),
    storage BLOB(4096) DEFAULT NULL,
    lm NUMBER(10),
    lrc NUMBER(10),
    lic NUMBER(10),
    leg_cseq NUMBER(10),
    leg_route CLOB,
    leg_tag VARCHAR2(64),
    leg_contact VARCHAR2(255),
    leg_sockinfo VARCHAR2(255),
    CONSTRAINT b2b_entities_b2b_entities_idx  UNIQUE (type, tag0, tag1, callid)
);

CREATE OR REPLACE TRIGGER b2b_entities_tr
before insert on b2b_entities FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END b2b_entities_tr;
/
BEGIN map2users('b2b_entities'); END;
/
CREATE INDEX ORA_b2b_entities_param  ON b2b_entities (param);

INSERT INTO version (table_name, table_version) values ('b2b_logic','3');
CREATE TABLE b2b_logic (
    id NUMBER(10) PRIMARY KEY,
    si_key VARCHAR2(64),
    scenario VARCHAR2(64),
    sstate NUMBER(10),
    next_sstate NUMBER(10),
    sparam0 VARCHAR2(64),
    sparam1 VARCHAR2(64),
    sparam2 VARCHAR2(64),
    sparam3 VARCHAR2(64),
    sparam4 VARCHAR2(64),
    sdp CLOB(64),
    lifetime NUMBER(10) DEFAULT 0 NOT NULL,
    e1_type NUMBER(10),
    e1_sid VARCHAR2(64),
    e1_from VARCHAR2(255),
    e1_to VARCHAR2(255),
    e1_key VARCHAR2(64),
    e2_type NUMBER(10),
    e2_sid VARCHAR2(64),
    e2_from VARCHAR2(255),
    e2_to VARCHAR2(255),
    e2_key VARCHAR2(64),
    e3_type NUMBER(10),
    e3_sid VARCHAR2(64),
    e3_from VARCHAR2(255),
    e3_to VARCHAR2(255),
    e3_key VARCHAR2(64),
    CONSTRAINT b2b_logic_b2b_logic_idx  UNIQUE (si_key)
);

CREATE OR REPLACE TRIGGER b2b_logic_tr
before insert on b2b_logic FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END b2b_logic_tr;
/
BEGIN map2users('b2b_logic'); END;
/
