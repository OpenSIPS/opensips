INSERT INTO version (table_name, table_version) values ('cc_flows','1');
CREATE TABLE cc_flows (
    id INT(10) UNSIGNED AUTO_INCREMENT NOT NULL,
    flowid CHAR(64) PRIMARY KEY NOT NULL,
    priority INT(11) UNSIGNED DEFAULT 256 NOT NULL,
    skill CHAR(64) NOT NULL,
    prependcid CHAR(32) NOT NULL,
    message_welcome CHAR(128) DEFAULT NULL,
    message_queue CHAR(128) NOT NULL
) ENGINE=MyISAM;

INSERT INTO version (table_name, table_version) values ('cc_agents','1');
CREATE TABLE cc_agents (
    id INT(10) UNSIGNED AUTO_INCREMENT NOT NULL,
    agentid CHAR(128) PRIMARY KEY NOT NULL,
    location CHAR(128) NOT NULL,
    logstate INT(10) UNSIGNED DEFAULT 0 NOT NULL,
    skills CHAR(512) NOT NULL
) ENGINE=MyISAM;

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
    call_type INT(11) UNSIGNED DEFAULT -1 NOT NULL,
    call_type INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    call_type INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    cid INT(11) UNSIGNED DEFAULT 0
) ENGINE=MyISAM;

