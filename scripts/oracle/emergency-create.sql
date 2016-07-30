INSERT INTO version (table_name, table_version) values ('emergency_routing','1');
CREATE TABLE emergency_routing (
    id NUMBER(10) PRIMARY KEY,
    selectiveRoutingID VARCHAR2(11),
    routingESN NUMBER(10) DEFAULT 0 NOT NULL,
    npa NUMBER(10) DEFAULT 0 NOT NULL,
    esgwri VARCHAR2(50)
);

CREATE OR REPLACE TRIGGER emergency_routing_tr
before insert on emergency_routing FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END emergency_routing_tr;
/
BEGIN map2users('emergency_routing'); END;
/
INSERT INTO version (table_name, table_version) values ('emergency_report','1');
CREATE TABLE emergency_report (
    id NUMBER(10) PRIMARY KEY,
    callid VARCHAR2(25),
    selectiveRoutingID VARCHAR2(11),
    routingESN NUMBER(10) DEFAULT 0 NOT NULL,
    npa NUMBER(10) DEFAULT 0 NOT NULL,
    esgwri VARCHAR2(50),
    lro VARCHAR2(20),
    VPC_organizationName VARCHAR2(50),
    VPC_hostname VARCHAR2(50),
    VPC_timestamp VARCHAR2(30),
    result VARCHAR2(4),
    disposition VARCHAR2(10)
);

CREATE OR REPLACE TRIGGER emergency_report_tr
before insert on emergency_report FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END emergency_report_tr;
/
BEGIN map2users('emergency_report'); END;
/
INSERT INTO version (table_name, table_version) values ('emergency_service_provider','1');
CREATE TABLE emergency_service_provider (
    id NUMBER(10) PRIMARY KEY,
    organizationName VARCHAR2(50),
    hostId VARCHAR2(30),
    nenaId VARCHAR2(50),
    contact VARCHAR2(20),
    certUri VARCHAR2(50),
    nodeIP VARCHAR2(20),
    attribution NUMBER(10)
);

CREATE OR REPLACE TRIGGER emergency_service_provider_tr
before insert on emergency_service_provider FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END emergency_service_provider_tr;
/
BEGIN map2users('emergency_service_provider'); END;
/
