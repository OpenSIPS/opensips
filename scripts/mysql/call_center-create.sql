INSERT INTO version (table_name, table_version) values ('cc_flows','2');
CREATE TABLE cc_flows (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    flowid CHAR(64) NOT NULL,
    priority INT(11) UNSIGNED DEFAULT 256 NOT NULL,
    skill CHAR(64) NOT NULL,
    prependcid CHAR(32) NOT NULL,
    max_wrapup_time INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    dissuading_hangup INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    dissuading_onhold_th INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    dissuading_ewt_th INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    dissuading_qsize_th INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    message_welcome CHAR(128) DEFAULT NULL,
    message_queue CHAR(128) NOT NULL,
    message_dissuading CHAR(128) NOT NULL,
    message_flow_id CHAR(128),
    CONSTRAINT unique_flowid UNIQUE (flowid)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('cc_agents','2');
CREATE TABLE cc_agents (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    agentid CHAR(128) NOT NULL,
    location CHAR(128) NOT NULL,
    logstate INT(10) UNSIGNED DEFAULT 0 NOT NULL,
    skills CHAR(255) NOT NULL,
    wrapup_end_time INT(11) DEFAULT 0 NOT NULL,
    wrapup_time INT(11) DEFAULT 0 NOT NULL,
    CONSTRAINT unique_agentid UNIQUE (agentid)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('cc_cdrs','1');
CREATE TABLE cc_cdrs (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    caller CHAR(64) NOT NULL,
    received_timestamp DATETIME NOT NULL,
    wait_time INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    pickup_time INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    talk_time INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    flow_id CHAR(128) NOT NULL,
    agent_id CHAR(128) DEFAULT NULL,
    call_type INT(11) DEFAULT -1 NOT NULL,
    rejected INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    fstats INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    cid INT(11) UNSIGNED DEFAULT 0
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('cc_calls','2');
CREATE TABLE cc_calls (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    state INT(11) NOT NULL,
    ig_cback INT(11) NOT NULL,
    no_rej INT(11) NOT NULL,
    setup_time INT(11) NOT NULL,
    eta INT(11) NOT NULL,
    last_start INT(11) NOT NULL,
    recv_time INT(11) NOT NULL,
    caller_dn CHAR(128) NOT NULL,
    caller_un CHAR(128) NOT NULL,
    b2buaid CHAR(128) DEFAULT '' NOT NULL,
    flow CHAR(128) NOT NULL,
    agent CHAR(128) NOT NULL,
    script_param CHAR(128) NOT NULL,
    CONSTRAINT unique_id UNIQUE (b2buaid)
) ENGINE=InnoDB;

CREATE INDEX b2buaid_idx ON cc_calls (b2buaid);

