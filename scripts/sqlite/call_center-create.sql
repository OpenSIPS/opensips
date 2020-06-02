INSERT INTO version (table_name, table_version) values ('cc_flows','2');
CREATE TABLE cc_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    flowid CHAR(64) NOT NULL,
    priority INTEGER DEFAULT 256 NOT NULL,
    skill CHAR(64) NOT NULL,
    prependcid CHAR(32) NOT NULL,
    max_wrapup_time INTEGER DEFAULT 0 NOT NULL,
    dissuading_hangup INTEGER DEFAULT 0 NOT NULL,
    dissuading_onhold_th INTEGER DEFAULT 0 NOT NULL,
    dissuading_ewt_th INTEGER DEFAULT 0 NOT NULL,
    dissuading_qsize_th INTEGER DEFAULT 0 NOT NULL,
    message_welcome CHAR(128) DEFAULT NULL,
    message_queue CHAR(128) NOT NULL,
    message_dissuading CHAR(128) NOT NULL,
    message_flow_id CHAR(128),
    CONSTRAINT cc_flows_unique_flowid  UNIQUE (flowid)
);

INSERT INTO version (table_name, table_version) values ('cc_agents','2');
CREATE TABLE cc_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    agentid CHAR(128) NOT NULL,
    location CHAR(128) NOT NULL,
    logstate INTEGER DEFAULT 0 NOT NULL,
    skills CHAR(255) NOT NULL,
    wrapup_end_time INTEGER DEFAULT 0 NOT NULL,
    wrapup_time INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT cc_agents_unique_agentid  UNIQUE (agentid)
);

INSERT INTO version (table_name, table_version) values ('cc_cdrs','1');
CREATE TABLE cc_cdrs (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    caller CHAR(64) NOT NULL,
    received_timestamp DATETIME NOT NULL,
    wait_time INTEGER DEFAULT 0 NOT NULL,
    pickup_time INTEGER DEFAULT 0 NOT NULL,
    talk_time INTEGER DEFAULT 0 NOT NULL,
    flow_id CHAR(128) NOT NULL,
    agent_id CHAR(128) DEFAULT NULL,
    call_type INTEGER DEFAULT -1 NOT NULL,
    rejected INTEGER DEFAULT 0 NOT NULL,
    fstats INTEGER DEFAULT 0 NOT NULL,
    cid INTEGER DEFAULT 0
);

INSERT INTO version (table_name, table_version) values ('cc_calls','2');
CREATE TABLE cc_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    state INTEGER NOT NULL,
    ig_cback INTEGER NOT NULL,
    no_rej INTEGER NOT NULL,
    setup_time INTEGER NOT NULL,
    eta INTEGER NOT NULL,
    last_start INTEGER NOT NULL,
    recv_time INTEGER NOT NULL,
    caller_dn CHAR(128) NOT NULL,
    caller_un CHAR(128) NOT NULL,
    b2buaid CHAR(128) DEFAULT '' NOT NULL,
    flow CHAR(128) NOT NULL,
    agent CHAR(128) NOT NULL,
    script_param CHAR(128) NOT NULL,
    CONSTRAINT cc_calls_unique_id  UNIQUE (b2buaid)
);

CREATE INDEX cc_calls_b2buaid_idx  ON cc_calls (b2buaid);

