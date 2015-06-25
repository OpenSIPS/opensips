INSERT INTO version (table_name, table_version) values ('emergency_routing','1');
CREATE TABLE emergency_routing (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    selectiveRoutingID CHAR(11) NOT NULL,
    routingESN INTEGER DEFAULT 0 NOT NULL,
    npa INTEGER DEFAULT 0 NOT NULL,
    esgwri CHAR(50) NOT NULL
);

INSERT INTO version (table_name, table_version) values ('emergency_report','1');
CREATE TABLE emergency_report (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    callid CHAR(25) NOT NULL,
    selectiveRoutingID CHAR(11) NOT NULL,
    routingESN INTEGER DEFAULT 0 NOT NULL,
    npa INTEGER DEFAULT 0 NOT NULL,
    esgwri CHAR(50) NOT NULL,
    lro CHAR(20) NOT NULL,
    VPC_organizationName CHAR(50) NOT NULL,
    VPC_hostname CHAR(50) NOT NULL,
    VPC_timestamp CHAR(30) NOT NULL,
    result CHAR(4) NOT NULL,
    disposition CHAR(10) NOT NULL
);

