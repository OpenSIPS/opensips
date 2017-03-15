INSERT INTO version (table_name, table_version) values ('location','1011');
CREATE TABLE location (
    contact_id  INTEGER PRIMARY KEY AUTOINCREMENT  NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT NULL,
    contact CHAR(255) DEFAULT '' NOT NULL,
    received CHAR(128) DEFAULT NULL,
    path CHAR(255) DEFAULT NULL,
    expires DATETIME DEFAULT '2020-05-28 21:32:15' NOT NULL,
    q FLOAT(10,2) DEFAULT 1.0 NOT NULL,
    callid CHAR(255) DEFAULT 'Default-Call-ID' NOT NULL,
    cseq INTEGER DEFAULT 13 NOT NULL,
    last_modified DATETIME DEFAULT '1900-01-01 00:00:01' NOT NULL,
    flags INTEGER DEFAULT 0 NOT NULL,
    cflags CHAR(255) DEFAULT NULL,
    user_agent CHAR(255) DEFAULT '' NOT NULL,
    socket CHAR(64) DEFAULT NULL,
    methods INTEGER DEFAULT NULL,
    sip_instance CHAR(255) DEFAULT NULL,
    attr CHAR(255) DEFAULT NULL
);

