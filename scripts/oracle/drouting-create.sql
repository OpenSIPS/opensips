INSERT INTO version (table_name, table_version) values ('dr_gateways','6');
CREATE TABLE dr_gateways (
    id NUMBER(10) PRIMARY KEY,
    gwid VARCHAR2(64),
    type NUMBER(10) DEFAULT 0 NOT NULL,
    address VARCHAR2(128),
    strip NUMBER(10) DEFAULT 0 NOT NULL,
    pri_prefix VARCHAR2(16) DEFAULT NULL,
    attrs VARCHAR2(255) DEFAULT NULL,
    probe_mode NUMBER(10) DEFAULT 0 NOT NULL,
    state NUMBER(10) DEFAULT 0 NOT NULL,
    socket VARCHAR2(128) DEFAULT NULL,
    description VARCHAR2(128) DEFAULT NULL,
    CONSTRAINT dr_gateways_dr_gw_idx  UNIQUE (gwid)
);

CREATE OR REPLACE TRIGGER dr_gateways_tr
before insert on dr_gateways FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END dr_gateways_tr;
/
BEGIN map2users('dr_gateways'); END;
/
INSERT INTO version (table_name, table_version) values ('dr_rules','4');
CREATE TABLE dr_rules (
    ruleid NUMBER(10) PRIMARY KEY,
    groupid VARCHAR2(255),
    prefix VARCHAR2(64),
    timerec VARCHAR2(255) DEFAULT NULL,
    priority NUMBER(10) DEFAULT 0 NOT NULL,
    routeid VARCHAR2(255) DEFAULT NULL,
    gwlist VARCHAR2(255),
    sort_alg VARCHAR2(1) DEFAULT 'N',
    sort_profile NUMBER(10) DEFAULT NULL,
    attrs VARCHAR2(255) DEFAULT NULL,
    description VARCHAR2(128) DEFAULT NULL
);

CREATE OR REPLACE TRIGGER dr_rules_tr
before insert on dr_rules FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END dr_rules_tr;
/
BEGIN map2users('dr_rules'); END;
/
INSERT INTO version (table_name, table_version) values ('dr_carriers','3');
CREATE TABLE dr_carriers (
    id NUMBER(10) PRIMARY KEY,
    carrierid VARCHAR2(64),
    gwlist VARCHAR2(255),
    flags NUMBER(10) DEFAULT 0 NOT NULL,
    sort_alg VARCHAR2(1) DEFAULT 'N',
    state NUMBER(10) DEFAULT 0 NOT NULL,
    attrs VARCHAR2(255) DEFAULT NULL,
    description VARCHAR2(128) DEFAULT NULL,
    CONSTRAINT dr_carriers_dr_carrier_idx  UNIQUE (carrierid)
);

CREATE OR REPLACE TRIGGER dr_carriers_tr
before insert on dr_carriers FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END dr_carriers_tr;
/
BEGIN map2users('dr_carriers'); END;
/
INSERT INTO version (table_name, table_version) values ('dr_groups','2');
CREATE TABLE dr_groups (
    id NUMBER(10) PRIMARY KEY,
    username VARCHAR2(64),
    domain VARCHAR2(128) DEFAULT NULL,
    groupid NUMBER(10) DEFAULT 0 NOT NULL,
    description VARCHAR2(128) DEFAULT NULL
);

CREATE OR REPLACE TRIGGER dr_groups_tr
before insert on dr_groups FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END dr_groups_tr;
/
BEGIN map2users('dr_groups'); END;
/
INSERT INTO version (table_name, table_version) values ('dr_partitions','1');
CREATE TABLE dr_partitions (
    id NUMBER(10) PRIMARY KEY,
    partition_name VARCHAR2(255),
    db_url VARCHAR2(255),
    drd_table VARCHAR2(255),
    drr_table VARCHAR2(255),
    drg_table VARCHAR2(255),
    drc_table VARCHAR2(255),
    ruri_avp VARCHAR2(255),
    gw_id_avp VARCHAR2(255),
    gw_priprefix_avp VARCHAR2(255),
    gw_sock_avp VARCHAR2(255),
    rule_id_avp VARCHAR2(255),
    rule_prefix_avp VARCHAR2(255),
    carrier_id_avp VARCHAR2(255)
);

CREATE OR REPLACE TRIGGER dr_partitions_tr
before insert on dr_partitions FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END dr_partitions_tr;
/
BEGIN map2users('dr_partitions'); END;
/
