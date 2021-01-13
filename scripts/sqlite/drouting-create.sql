INSERT INTO version (table_name, table_version) values ('dr_gateways','6');
CREATE TABLE dr_gateways (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    gwid CHAR(64) NOT NULL,
    type INTEGER DEFAULT 0 NOT NULL,
    address CHAR(128) NOT NULL,
    strip INTEGER DEFAULT 0 NOT NULL,
    pri_prefix CHAR(16) DEFAULT NULL,
    attrs CHAR(255) DEFAULT NULL,
    probe_mode INTEGER DEFAULT 0 NOT NULL,
    state INTEGER DEFAULT 0 NOT NULL,
    socket CHAR(128) DEFAULT NULL,
    description CHAR(128) DEFAULT NULL,
    CONSTRAINT dr_gateways_dr_gw_idx  UNIQUE (gwid)
);

INSERT INTO version (table_name, table_version) values ('dr_rules','4');
CREATE TABLE dr_rules (
    ruleid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    groupid CHAR(255) NOT NULL,
    prefix CHAR(64) NOT NULL,
    timerec CHAR(255) DEFAULT NULL,
    priority INTEGER DEFAULT 0 NOT NULL,
    routeid CHAR(255) DEFAULT NULL,
    gwlist CHAR(255) NOT NULL,
    sort_alg CHAR(1) DEFAULT 'N' NOT NULL,
    sort_profile INTEGER DEFAULT NULL,
    attrs CHAR(255) DEFAULT NULL,
    description CHAR(128) DEFAULT NULL
);

INSERT INTO version (table_name, table_version) values ('dr_carriers','3');
CREATE TABLE dr_carriers (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    carrierid CHAR(64) NOT NULL,
    gwlist CHAR(255) NOT NULL,
    flags INTEGER DEFAULT 0 NOT NULL,
    sort_alg CHAR(1) DEFAULT 'N' NOT NULL,
    state INTEGER DEFAULT 0 NOT NULL,
    attrs CHAR(255) DEFAULT NULL,
    description CHAR(128) DEFAULT NULL,
    CONSTRAINT dr_carriers_dr_carrier_idx  UNIQUE (carrierid)
);

INSERT INTO version (table_name, table_version) values ('dr_groups','2');
CREATE TABLE dr_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username CHAR(64) NOT NULL,
    domain CHAR(128) DEFAULT NULL,
    groupid INTEGER DEFAULT 0 NOT NULL,
    description CHAR(128) DEFAULT NULL
);

INSERT INTO version (table_name, table_version) values ('dr_partitions','1');
CREATE TABLE dr_partitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    partition_name CHAR(255) NOT NULL,
    db_url CHAR(255) NOT NULL,
    drd_table CHAR(255),
    drr_table CHAR(255),
    drg_table CHAR(255),
    drc_table CHAR(255),
    ruri_avp CHAR(255),
    gw_id_avp CHAR(255),
    gw_priprefix_avp CHAR(255),
    gw_sock_avp CHAR(255),
    rule_id_avp CHAR(255),
    rule_prefix_avp CHAR(255),
    carrier_id_avp CHAR(255)
);

