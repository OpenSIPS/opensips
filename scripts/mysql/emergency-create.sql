INSERT INTO version (table_name, table_version) values ('emergency_routing','1');
CREATE TABLE emergency_routing (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    selectiveRoutingID CHAR(11) NOT NULL,
    routingESN INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    npa INT(3) UNSIGNED DEFAULT 0 NOT NULL,
    esgwri CHAR(50) NOT NULL
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('emergency_report','1');
CREATE TABLE emergency_report (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    callid CHAR(25) NOT NULL,
    selectiveRoutingID CHAR(11) NOT NULL,
    routingESN INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    npa INT(3) UNSIGNED DEFAULT 0 NOT NULL,
    esgwri CHAR(50) NOT NULL,
    lro CHAR(20) NOT NULL,
    VPC_organizationName CHAR(50) NOT NULL,
    VPC_hostname CHAR(50) NOT NULL,
    VPC_timestamp CHAR(30) NOT NULL,
    result CHAR(4) NOT NULL,
    disposition CHAR(10) NOT NULL
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('emergency_service_provider','1');
CREATE TABLE emergency_service_provider (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    organizationName CHAR(50) NOT NULL,
    hostId CHAR(30) NOT NULL,
    nenaId CHAR(50) NOT NULL,
    contact CHAR(20) NOT NULL,
    certUri CHAR(50) NOT NULL,
    nodeIP CHAR(20) NOT NULL,
    attribution INT(2) UNSIGNED NOT NULL
) ENGINE=InnoDB;

