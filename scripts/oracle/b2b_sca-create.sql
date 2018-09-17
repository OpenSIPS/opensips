INSERT INTO version (table_name, table_version) values ('b2b_sca','1');
CREATE TABLE b2b_sca (
    id NUMBER(10) PRIMARY KEY,
    shared_line VARCHAR2(64),
    watchers VARCHAR2(255),
    app1_shared_entity NUMBER(10) DEFAULT NULL,
    app1_call_state NUMBER(10) DEFAULT NULL,
    app1_call_info_uri VARCHAR2(255) DEFAULT NULL,
    app1_call_info_appearance_uri VARCHAR2(255) DEFAULT NULL,
    app1_b2bl_key VARCHAR2(64) DEFAULT NULL,
    app2_shared_entity NUMBER(10) DEFAULT NULL,
    app2_call_state NUMBER(10) DEFAULT NULL,
    app2_call_info_uri VARCHAR2(255) DEFAULT NULL,
    app2_call_info_appearance_uri VARCHAR2(255) DEFAULT NULL,
    app2_b2bl_key VARCHAR2(64) DEFAULT NULL,
    app3_shared_entity NUMBER(10) DEFAULT NULL,
    app3_call_state NUMBER(10) DEFAULT NULL,
    app3_call_info_uri VARCHAR2(255) DEFAULT NULL,
    app3_call_info_appearance_uri VARCHAR2(255) DEFAULT NULL,
    app3_b2bl_key VARCHAR2(64) DEFAULT NULL,
    app4_shared_entity NUMBER(10) DEFAULT NULL,
    app4_call_state NUMBER(10) DEFAULT NULL,
    app4_call_info_uri VARCHAR2(255) DEFAULT NULL,
    app4_call_info_appearance_uri VARCHAR2(255) DEFAULT NULL,
    app4_b2bl_key VARCHAR2(64) DEFAULT NULL,
    app5_shared_entity NUMBER(10) DEFAULT NULL,
    app5_call_state NUMBER(10) DEFAULT NULL,
    app5_call_info_uri VARCHAR2(255) DEFAULT NULL,
    app5_call_info_appearance_uri VARCHAR2(255) DEFAULT NULL,
    app5_b2bl_key VARCHAR2(64) DEFAULT NULL,
    app6_shared_entity NUMBER(10) DEFAULT NULL,
    app6_call_state NUMBER(10) DEFAULT NULL,
    app6_call_info_uri VARCHAR2(255) DEFAULT NULL,
    app6_call_info_appearance_uri VARCHAR2(255) DEFAULT NULL,
    app6_b2bl_key VARCHAR2(64) DEFAULT NULL,
    app7_shared_entity NUMBER(10) DEFAULT NULL,
    app7_call_state NUMBER(10) DEFAULT NULL,
    app7_call_info_uri VARCHAR2(255) DEFAULT NULL,
    app7_call_info_appearance_uri VARCHAR2(255) DEFAULT NULL,
    app7_b2bl_key VARCHAR2(64) DEFAULT NULL,
    app8_shared_entity NUMBER(10) DEFAULT NULL,
    app8_call_state NUMBER(10) DEFAULT NULL,
    app8_call_info_uri VARCHAR2(255) DEFAULT NULL,
    app8_call_info_appearance_uri VARCHAR2(255) DEFAULT NULL,
    app8_b2bl_key VARCHAR2(64) DEFAULT NULL,
    app9_shared_entity NUMBER(10) DEFAULT NULL,
    app9_call_state NUMBER(10) DEFAULT NULL,
    app9_call_info_uri VARCHAR2(255) DEFAULT NULL,
    app9_call_info_appearance_uri VARCHAR2(255) DEFAULT NULL,
    app9_b2bl_key VARCHAR2(64) DEFAULT NULL,
    app10_shared_entity NUMBER(10) DEFAULT NULL,
    app10_call_state NUMBER(10) DEFAULT NULL,
    app10_call_info_uri VARCHAR2(255) DEFAULT NULL,
    app10_call_info_appearance_uri VARCHAR2(255) DEFAULT NULL,
    app10_b2bl_key VARCHAR2(64) DEFAULT NULL,
    CONSTRAINT b2b_sca_sca_idx  UNIQUE (shared_line)
);

CREATE OR REPLACE TRIGGER b2b_sca_tr
before insert on b2b_sca FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END b2b_sca_tr;
/
BEGIN map2users('b2b_sca'); END;
/
