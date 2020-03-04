INSERT INTO version (table_name, table_version) values ('b2b_entities','2');
CREATE TABLE b2b_entities (
    id SERIAL PRIMARY KEY NOT NULL,
    type INTEGER NOT NULL,
    state INTEGER NOT NULL,
    ruri VARCHAR(255),
    from_uri VARCHAR(255) NOT NULL,
    to_uri VARCHAR(255) NOT NULL,
    from_dname VARCHAR(64),
    to_dname VARCHAR(64),
    tag0 VARCHAR(64) NOT NULL,
    tag1 VARCHAR(64),
    callid VARCHAR(64) NOT NULL,
    cseq0 INTEGER NOT NULL,
    cseq1 INTEGER,
    contact0 VARCHAR(255) NOT NULL,
    contact1 VARCHAR(255),
    route0 TEXT,
    route1 TEXT,
    sockinfo_srv VARCHAR(64),
    param VARCHAR(255) NOT NULL,
    mod_name VARCHAR(32) NOT NULL,
    storage BYTEA DEFAULT NULL,
    lm INTEGER NOT NULL,
    lrc INTEGER,
    lic INTEGER,
    leg_cseq INTEGER,
    leg_route TEXT,
    leg_tag VARCHAR(64),
    leg_contact VARCHAR(255),
    leg_sockinfo VARCHAR(255),
    CONSTRAINT b2b_entities_b2b_entities_idx UNIQUE (type, tag0, tag1, callid)
);

ALTER SEQUENCE b2b_entities_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX b2b_entities_b2b_entities_param ON b2b_entities (param);

INSERT INTO version (table_name, table_version) values ('b2b_logic','3');
CREATE TABLE b2b_logic (
    id SERIAL PRIMARY KEY NOT NULL,
    si_key VARCHAR(64) NOT NULL,
    scenario VARCHAR(64),
    sstate INTEGER NOT NULL,
    next_sstate INTEGER NOT NULL,
    sparam0 VARCHAR(64),
    sparam1 VARCHAR(64),
    sparam2 VARCHAR(64),
    sparam3 VARCHAR(64),
    sparam4 VARCHAR(64),
    sdp TEXT,
    lifetime INTEGER DEFAULT 0 NOT NULL,
    e1_type INTEGER NOT NULL,
    e1_sid VARCHAR(64),
    e1_from VARCHAR(255) NOT NULL,
    e1_to VARCHAR(255) NOT NULL,
    e1_key VARCHAR(64) NOT NULL,
    e2_type INTEGER NOT NULL,
    e2_sid VARCHAR(64),
    e2_from VARCHAR(255) NOT NULL,
    e2_to VARCHAR(255) NOT NULL,
    e2_key VARCHAR(64) NOT NULL,
    e3_type INTEGER,
    e3_sid VARCHAR(64),
    e3_from VARCHAR(255),
    e3_to VARCHAR(255),
    e3_key VARCHAR(64),
    CONSTRAINT b2b_logic_b2b_logic_idx UNIQUE (si_key)
);

ALTER SEQUENCE b2b_logic_id_seq MAXVALUE 2147483647 CYCLE;
