INSERT INTO version (table_name, table_version) values ('sip_trace','5');
CREATE TABLE sip_trace (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    time_stamp DATETIME DEFAULT '1900-01-01 00:00:01' NOT NULL,
    callid CHAR(255) DEFAULT '' NOT NULL,
    trace_attrs CHAR(255) DEFAULT NULL,
    msg TEXT NOT NULL,
    method CHAR(32) DEFAULT '' NOT NULL,
    status CHAR(255) DEFAULT NULL,
    from_proto CHAR(5) NOT NULL,
    from_ip CHAR(50) DEFAULT '' NOT NULL,
    from_port INTEGER NOT NULL,
    to_proto CHAR(5) NOT NULL,
    to_ip CHAR(50) DEFAULT '' NOT NULL,
    to_port INTEGER NOT NULL,
    fromtag CHAR(64) DEFAULT '' NOT NULL,
    direction CHAR(4) DEFAULT '' NOT NULL
);

CREATE INDEX sip_trace_trace_attrs_idx  ON sip_trace (trace_attrs);
CREATE INDEX sip_trace_date_idx  ON sip_trace (time_stamp);
CREATE INDEX sip_trace_fromip_idx  ON sip_trace (from_ip);
CREATE INDEX sip_trace_callid_idx  ON sip_trace (callid);

