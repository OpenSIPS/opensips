INSERT INTO version (table_name, table_version) values ('sip_trace','5');
CREATE TABLE sip_trace (
    id SERIAL PRIMARY KEY NOT NULL,
    time_stamp TIMESTAMP WITHOUT TIME ZONE DEFAULT '1900-01-01 00:00:01' NOT NULL,
    callid VARCHAR(255) DEFAULT '' NOT NULL,
    trace_attrs VARCHAR(255) DEFAULT NULL,
    msg TEXT NOT NULL,
    method VARCHAR(32) DEFAULT '' NOT NULL,
    status VARCHAR(255) DEFAULT NULL,
    from_proto VARCHAR(5) NOT NULL,
    from_ip VARCHAR(50) DEFAULT '' NOT NULL,
    from_port INTEGER NOT NULL,
    to_proto VARCHAR(5) NOT NULL,
    to_ip VARCHAR(50) DEFAULT '' NOT NULL,
    to_port INTEGER NOT NULL,
    fromtag VARCHAR(64) DEFAULT '' NOT NULL,
    direction VARCHAR(4) DEFAULT '' NOT NULL
);

ALTER SEQUENCE sip_trace_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX sip_trace_trace_attrs_idx ON sip_trace (trace_attrs);
CREATE INDEX sip_trace_date_idx ON sip_trace (time_stamp);
CREATE INDEX sip_trace_fromip_idx ON sip_trace (from_ip);
CREATE INDEX sip_trace_callid_idx ON sip_trace (callid);

