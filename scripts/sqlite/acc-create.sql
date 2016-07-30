INSERT INTO version (table_name, table_version) values ('acc','7');
CREATE TABLE acc (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    method CHAR(16) DEFAULT '' NOT NULL,
    from_tag CHAR(64) DEFAULT '' NOT NULL,
    to_tag CHAR(64) DEFAULT '' NOT NULL,
    callid CHAR(64) DEFAULT '' NOT NULL,
    sip_code CHAR(3) DEFAULT '' NOT NULL,
    sip_reason CHAR(32) DEFAULT '' NOT NULL,
    time DATETIME NOT NULL,
    duration INTEGER DEFAULT 0 NOT NULL,
    ms_duration INTEGER DEFAULT 0 NOT NULL,
    setuptime INTEGER DEFAULT 0 NOT NULL,
    created DATETIME DEFAULT NULL
);

CREATE INDEX acc_callid_idx  ON acc (callid);

INSERT INTO version (table_name, table_version) values ('missed_calls','5');
CREATE TABLE missed_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    method CHAR(16) DEFAULT '' NOT NULL,
    from_tag CHAR(64) DEFAULT '' NOT NULL,
    to_tag CHAR(64) DEFAULT '' NOT NULL,
    callid CHAR(64) DEFAULT '' NOT NULL,
    sip_code CHAR(3) DEFAULT '' NOT NULL,
    sip_reason CHAR(32) DEFAULT '' NOT NULL,
    time DATETIME NOT NULL,
    setuptime INTEGER DEFAULT 0 NOT NULL,
    created DATETIME DEFAULT NULL
);

CREATE INDEX missed_calls_callid_idx  ON missed_calls (callid);

