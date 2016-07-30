INSERT INTO version (table_name, table_version) values ('emergency_routing','1');
CREATE TABLE emergency_routing (
    id SERIAL PRIMARY KEY NOT NULL,
    selectiveRoutingID VARCHAR(11) NOT NULL,
    routingESN INTEGER DEFAULT 0 NOT NULL,
    npa INTEGER DEFAULT 0 NOT NULL,
    esgwri VARCHAR(50) NOT NULL
);

ALTER SEQUENCE emergency_routing_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('emergency_report','1');
CREATE TABLE emergency_report (
    id SERIAL PRIMARY KEY NOT NULL,
    callid VARCHAR(25) NOT NULL,
    selectiveRoutingID VARCHAR(11) NOT NULL,
    routingESN INTEGER DEFAULT 0 NOT NULL,
    npa INTEGER DEFAULT 0 NOT NULL,
    esgwri VARCHAR(50) NOT NULL,
    lro VARCHAR(20) NOT NULL,
    VPC_organizationName VARCHAR(50) NOT NULL,
    VPC_hostname VARCHAR(50) NOT NULL,
    VPC_timestamp VARCHAR(30) NOT NULL,
    result VARCHAR(4) NOT NULL,
    disposition VARCHAR(10) NOT NULL
);

ALTER SEQUENCE emergency_report_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('emergency_service_provider','1');
CREATE TABLE emergency_service_provider (
    id SERIAL PRIMARY KEY NOT NULL,
    organizationName VARCHAR(50) NOT NULL,
    hostId VARCHAR(30) NOT NULL,
    nenaId VARCHAR(50) NOT NULL,
    contact VARCHAR(20) NOT NULL,
    certUri VARCHAR(50) NOT NULL,
    nodeIP VARCHAR(20) NOT NULL,
    attribution INTEGER NOT NULL
);

ALTER SEQUENCE emergency_service_provider_id_seq MAXVALUE 2147483647 CYCLE;
