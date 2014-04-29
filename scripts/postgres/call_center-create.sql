INSERT INTO version (table_name, table_version) values ('cc_flows','1');
CREATE TABLE cc_flows (
    id SERIAL PRIMARY KEY NOT NULL,
    flowid VARCHAR(64) NOT NULL,
    priority INTEGER DEFAULT 256 NOT NULL,
    skill VARCHAR(64) NOT NULL,
    prependcid VARCHAR(32) NOT NULL,
    message_welcome VARCHAR(128) DEFAULT NULL,
    message_queue VARCHAR(128) NOT NULL,
    CONSTRAINT cc_flows_unique_flowid UNIQUE (flowid)
);
ALTER SEQUENCE cc_flows_id_seq MAXVALUE 2147483647 CYCLE;

INSERT INTO version (table_name, table_version) values ('cc_agents','1');
CREATE TABLE cc_agents (
    id SERIAL PRIMARY KEY NOT NULL,
    agentid VARCHAR(128) NOT NULL,
    location VARCHAR(128) NOT NULL,
    logstate INTEGER DEFAULT 0 NOT NULL,
    skills VARCHAR(255) NOT NULL,
    CONSTRAINT cc_agents_unique_agentid UNIQUE (agentid)
);

INSERT INTO version (table_name, table_version) values ('cc_cdrs','1');
CREATE TABLE cc_cdrs (
    id SERIAL PRIMARY KEY NOT NULL,
    caller VARCHAR(64) NOT NULL,
    received_timestamp TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    wait_time INTEGER DEFAULT 0 NOT NULL,
    pickup_time INTEGER DEFAULT 0 NOT NULL,
    talk_time INTEGER DEFAULT 0 NOT NULL,
    flow_id VARCHAR(128) NOT NULL,
    agent_id VARCHAR(128) DEFAULT NULL,
    call_type INTEGER DEFAULT -1 NOT NULL,
    rejected INTEGER DEFAULT 0 NOT NULL,
    fstats INTEGER DEFAULT 0 NOT NULL,
    cid INTEGER DEFAULT 0
);
ALTER SEQUENCE cc_cdrs_id_seq MAXVALUE 2147483647 CYCLE;
