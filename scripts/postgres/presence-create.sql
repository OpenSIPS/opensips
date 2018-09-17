INSERT INTO version (table_name, table_version) values ('presentity','5');
CREATE TABLE presentity (
    id SERIAL PRIMARY KEY NOT NULL,
    username VARCHAR(64) NOT NULL,
    domain VARCHAR(64) NOT NULL,
    event VARCHAR(64) NOT NULL,
    etag VARCHAR(64) NOT NULL,
    expires INTEGER NOT NULL,
    received_time INTEGER NOT NULL,
    body BYTEA DEFAULT NULL,
    extra_hdrs BYTEA DEFAULT NULL,
    sender VARCHAR(255) DEFAULT NULL,
    CONSTRAINT presentity_presentity_idx UNIQUE (username, domain, event, etag)
);

ALTER SEQUENCE presentity_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('active_watchers','12');
CREATE TABLE active_watchers (
    id SERIAL PRIMARY KEY NOT NULL,
    presentity_uri VARCHAR(255) NOT NULL,
    watcher_username VARCHAR(64) NOT NULL,
    watcher_domain VARCHAR(64) NOT NULL,
    to_user VARCHAR(64) NOT NULL,
    to_domain VARCHAR(64) NOT NULL,
    event VARCHAR(64) DEFAULT 'presence' NOT NULL,
    event_id VARCHAR(64),
    to_tag VARCHAR(64) NOT NULL,
    from_tag VARCHAR(64) NOT NULL,
    callid VARCHAR(64) NOT NULL,
    local_cseq INTEGER NOT NULL,
    remote_cseq INTEGER NOT NULL,
    contact VARCHAR(255) NOT NULL,
    record_route TEXT,
    expires INTEGER NOT NULL,
    status INTEGER DEFAULT 2 NOT NULL,
    reason VARCHAR(64),
    version INTEGER DEFAULT 0 NOT NULL,
    socket_info VARCHAR(64) NOT NULL,
    local_contact VARCHAR(255) NOT NULL,
    sharing_tag VARCHAR(32) DEFAULT NULL,
    CONSTRAINT active_watchers_active_watchers_idx UNIQUE (presentity_uri, callid, to_tag, from_tag)
);

ALTER SEQUENCE active_watchers_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('watchers','4');
CREATE TABLE watchers (
    id SERIAL PRIMARY KEY NOT NULL,
    presentity_uri VARCHAR(255) NOT NULL,
    watcher_username VARCHAR(64) NOT NULL,
    watcher_domain VARCHAR(64) NOT NULL,
    event VARCHAR(64) DEFAULT 'presence' NOT NULL,
    status INTEGER NOT NULL,
    reason VARCHAR(64),
    inserted_time INTEGER NOT NULL,
    CONSTRAINT watchers_watcher_idx UNIQUE (presentity_uri, watcher_username, watcher_domain, event)
);

ALTER SEQUENCE watchers_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('xcap','4');
CREATE TABLE xcap (
    id SERIAL PRIMARY KEY NOT NULL,
    username VARCHAR(64) NOT NULL,
    domain VARCHAR(64) NOT NULL,
    doc BYTEA NOT NULL,
    doc_type INTEGER NOT NULL,
    etag VARCHAR(64) NOT NULL,
    source INTEGER NOT NULL,
    doc_uri VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    CONSTRAINT xcap_account_doc_type_idx UNIQUE (username, domain, doc_type, doc_uri)
);

ALTER SEQUENCE xcap_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX xcap_source_idx ON xcap (source);

INSERT INTO version (table_name, table_version) values ('pua','8');
CREATE TABLE pua (
    id SERIAL PRIMARY KEY NOT NULL,
    pres_uri VARCHAR(255) NOT NULL,
    pres_id VARCHAR(255) NOT NULL,
    event INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    desired_expires INTEGER NOT NULL,
    flag INTEGER NOT NULL,
    etag VARCHAR(64),
    tuple_id VARCHAR(64),
    watcher_uri VARCHAR(255),
    to_uri VARCHAR(255),
    call_id VARCHAR(64),
    to_tag VARCHAR(64),
    from_tag VARCHAR(64),
    cseq INTEGER,
    record_route TEXT,
    contact VARCHAR(255),
    remote_contact VARCHAR(255),
    version INTEGER,
    extra_headers TEXT
);

ALTER SEQUENCE pua_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX pua_del1_idx ON pua (pres_uri, event);
CREATE INDEX pua_del2_idx ON pua (expires);
CREATE INDEX pua_update_idx ON pua (pres_uri, pres_id, flag, event);

