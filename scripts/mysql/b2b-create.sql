INSERT INTO version (table_name, table_version) values ('b2b_entities','2');
CREATE TABLE b2b_entities (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    type INT(2) NOT NULL,
    state INT(2) NOT NULL,
    ruri CHAR(255),
    from_uri CHAR(255) NOT NULL,
    to_uri CHAR(255) NOT NULL,
    from_dname CHAR(64),
    to_dname CHAR(64),
    tag0 CHAR(64) NOT NULL,
    tag1 CHAR(64),
    callid CHAR(64) NOT NULL,
    cseq0 INT(11) NOT NULL,
    cseq1 INT(11),
    contact0 CHAR(255) NOT NULL,
    contact1 CHAR(255),
    route0 TEXT,
    route1 TEXT,
    sockinfo_srv CHAR(64),
    param CHAR(255) NOT NULL,
    mod_name CHAR(32) NOT NULL,
    storage BLOB(4096) DEFAULT NULL,
    lm INT(11) NOT NULL,
    lrc INT(11),
    lic INT(11),
    leg_cseq INT(11),
    leg_route TEXT,
    leg_tag CHAR(64),
    leg_contact CHAR(255),
    leg_sockinfo CHAR(255),
    CONSTRAINT b2b_entities_idx UNIQUE (type, tag0, tag1, callid)
) ENGINE=InnoDB;

CREATE INDEX b2b_entities_param ON b2b_entities (param);

INSERT INTO version (table_name, table_version) values ('b2b_logic','4');
CREATE TABLE b2b_logic (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    si_key CHAR(64) NOT NULL,
    scenario CHAR(64),
    sstate INT(2) NOT NULL,
    sdp TEXT(64),
    lifetime INT(10) DEFAULT 0 NOT NULL,
    e1_type INT(2) NOT NULL,
    e1_sid CHAR(64),
    e1_from CHAR(255) NOT NULL,
    e1_to CHAR(255) NOT NULL,
    e1_key CHAR(64) NOT NULL,
    e2_type INT(2) NOT NULL,
    e2_sid CHAR(64),
    e2_from CHAR(255) NOT NULL,
    e2_to CHAR(255) NOT NULL,
    e2_key CHAR(64) NOT NULL,
    e3_type INT(2),
    e3_sid CHAR(64),
    e3_from CHAR(255),
    e3_to CHAR(255),
    e3_key CHAR(64),
    CONSTRAINT b2b_logic_idx UNIQUE (si_key)
) ENGINE=InnoDB;

