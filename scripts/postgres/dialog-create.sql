INSERT INTO version (table_name, table_version) values ('dialog','7');
CREATE TABLE dialog (
    id SERIAL PRIMARY KEY NOT NULL,
    hash_entry INTEGER NOT NULL,
    hash_id INTEGER NOT NULL,
    callid VARCHAR(255) NOT NULL,
    from_uri VARCHAR(128) NOT NULL,
    from_tag VARCHAR(64) NOT NULL,
    to_uri VARCHAR(128) NOT NULL,
    to_tag VARCHAR(64) NOT NULL,
    mangled_from_uri VARCHAR(64) DEFAULT NULL,
    mangled_to_uri VARCHAR(64) DEFAULT NULL,
    caller_cseq VARCHAR(11) NOT NULL,
    callee_cseq VARCHAR(11) NOT NULL,
    caller_ping_cseq INTEGER NOT NULL,
    callee_ping_cseq INTEGER NOT NULL,
    caller_route_set TEXT,
    callee_route_set TEXT,
    caller_contact VARCHAR(128) NOT NULL,
    callee_contact VARCHAR(128) NOT NULL,
    caller_sock VARCHAR(64) NOT NULL,
    callee_sock VARCHAR(64) NOT NULL,
    state INTEGER NOT NULL,
    start_time INTEGER NOT NULL,
    timeout INTEGER NOT NULL,
    vars TEXT DEFAULT NULL,
    profiles TEXT DEFAULT NULL,
    script_flags INTEGER DEFAULT 0 NOT NULL,
    flags INTEGER DEFAULT 0 NOT NULL
);

CREATE INDEX dialog_hash_idx ON dialog (hash_entry, hash_id);

