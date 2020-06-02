INSERT INTO version (table_name, table_version) values ('cc_flows','2');
CREATE TABLE cc_flows (
    id NUMBER(10) PRIMARY KEY,
    flowid VARCHAR2(64),
    priority NUMBER(10) DEFAULT 256 NOT NULL,
    skill VARCHAR2(64),
    prependcid VARCHAR2(32),
    max_wrapup_time NUMBER(10) DEFAULT 0 NOT NULL,
    dissuading_hangup NUMBER(10) DEFAULT 0 NOT NULL,
    dissuading_onhold_th NUMBER(10) DEFAULT 0 NOT NULL,
    dissuading_ewt_th NUMBER(10) DEFAULT 0 NOT NULL,
    dissuading_qsize_th NUMBER(10) DEFAULT 0 NOT NULL,
    message_welcome VARCHAR2(128) DEFAULT NULL,
    message_queue VARCHAR2(128),
    message_dissuading VARCHAR2(128),
    message_flow_id VARCHAR2(128),
    CONSTRAINT cc_flows_unique_flowid  UNIQUE (flowid)
);

CREATE OR REPLACE TRIGGER cc_flows_tr
before insert on cc_flows FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END cc_flows_tr;
/
BEGIN map2users('cc_flows'); END;
/
INSERT INTO version (table_name, table_version) values ('cc_agents','2');
CREATE TABLE cc_agents (
    id NUMBER(10) PRIMARY KEY,
    agentid VARCHAR2(128),
    location VARCHAR2(128),
    logstate NUMBER(10) DEFAULT 0 NOT NULL,
    skills VARCHAR2(255),
    wrapup_end_time NUMBER(10) DEFAULT 0 NOT NULL,
    wrapup_time NUMBER(10) DEFAULT 0 NOT NULL,
    CONSTRAINT cc_agents_unique_agentid  UNIQUE (agentid)
);

CREATE OR REPLACE TRIGGER cc_agents_tr
before insert on cc_agents FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END cc_agents_tr;
/
BEGIN map2users('cc_agents'); END;
/
INSERT INTO version (table_name, table_version) values ('cc_cdrs','1');
CREATE TABLE cc_cdrs (
    id NUMBER(10) PRIMARY KEY,
    caller VARCHAR2(64),
    received_timestamp DATE,
    wait_time NUMBER(10) DEFAULT 0 NOT NULL,
    pickup_time NUMBER(10) DEFAULT 0 NOT NULL,
    talk_time NUMBER(10) DEFAULT 0 NOT NULL,
    flow_id VARCHAR2(128),
    agent_id VARCHAR2(128) DEFAULT NULL,
    call_type NUMBER(10) DEFAULT -1 NOT NULL,
    rejected NUMBER(10) DEFAULT 0 NOT NULL,
    fstats NUMBER(10) DEFAULT 0 NOT NULL,
    cid NUMBER(10) DEFAULT 0
);

CREATE OR REPLACE TRIGGER cc_cdrs_tr
before insert on cc_cdrs FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END cc_cdrs_tr;
/
BEGIN map2users('cc_cdrs'); END;
/
INSERT INTO version (table_name, table_version) values ('cc_calls','2');
CREATE TABLE cc_calls (
    id NUMBER(10) PRIMARY KEY,
    state NUMBER(10),
    ig_cback NUMBER(10),
    no_rej NUMBER(10),
    setup_time NUMBER(10),
    eta NUMBER(10),
    last_start NUMBER(10),
    recv_time NUMBER(10),
    caller_dn VARCHAR2(128),
    caller_un VARCHAR2(128),
    b2buaid VARCHAR2(128) DEFAULT '',
    flow VARCHAR2(128),
    agent VARCHAR2(128),
    script_param VARCHAR2(128),
    CONSTRAINT cc_calls_unique_id  UNIQUE (b2buaid)
);

CREATE OR REPLACE TRIGGER cc_calls_tr
before insert on cc_calls FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END cc_calls_tr;
/
BEGIN map2users('cc_calls'); END;
/
CREATE INDEX cc_calls_b2buaid_idx  ON cc_calls (b2buaid);

