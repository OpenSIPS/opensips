INSERT INTO version (table_name, table_version) values ('dialog','12');
CREATE TABLE dialog (
    dlg_id BIGINT PRIMARY KEY NOT NULL,
    callid VARCHAR(255) NOT NULL,
    from_uri VARCHAR(255) NOT NULL,
    from_tag VARCHAR(64) NOT NULL,
    to_uri VARCHAR(255) NOT NULL,
    to_tag VARCHAR(64) NOT NULL,
    mangled_from_uri VARCHAR(255) DEFAULT NULL,
    mangled_to_uri VARCHAR(255) DEFAULT NULL,
    caller_cseq VARCHAR(11) NOT NULL,
    callee_cseq VARCHAR(11) NOT NULL,
    caller_ping_cseq INTEGER NOT NULL,
    callee_ping_cseq INTEGER NOT NULL,
    caller_route_set TEXT,
    callee_route_set TEXT,
    caller_contact VARCHAR(255),
    callee_contact VARCHAR(255),
    caller_sock VARCHAR(64) NOT NULL,
    callee_sock VARCHAR(64) NOT NULL,
    state INTEGER NOT NULL,
    start_time INTEGER NOT NULL,
    timeout INTEGER NOT NULL,
    vars BYTEA DEFAULT NULL,
    profiles TEXT DEFAULT NULL,
    script_flags VARCHAR(255) DEFAULT NULL,
    module_flags INTEGER DEFAULT 0 NOT NULL,
    flags INTEGER DEFAULT 0 NOT NULL,
    rt_on_answer VARCHAR(64) DEFAULT NULL,
    rt_on_timeout VARCHAR(64) DEFAULT NULL,
    rt_on_hangup VARCHAR(64) DEFAULT NULL
);

