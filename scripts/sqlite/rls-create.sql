INSERT INTO version (table_name, table_version) values ('rls_presentity','1');
CREATE TABLE rls_presentity (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    rlsubs_did CHAR(255) NOT NULL,
    resource_uri CHAR(255) NOT NULL,
    content_type CHAR(255) NOT NULL,
    presence_state BLOB NOT NULL,
    expires INTEGER NOT NULL,
    updated INTEGER NOT NULL,
    auth_state INTEGER NOT NULL,
    reason CHAR(64) NOT NULL,
    CONSTRAINT ORA_rls_presentity_idx  UNIQUE (rlsubs_did, resource_uri)
);

CREATE INDEX rls_presentity_updated_idx  ON rls_presentity (updated);

INSERT INTO version (table_name, table_version) values ('rls_watchers','2');
CREATE TABLE rls_watchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    presentity_uri CHAR(255) NOT NULL,
    to_user CHAR(64) NOT NULL,
    to_domain CHAR(64) NOT NULL,
    watcher_username CHAR(64) NOT NULL,
    watcher_domain CHAR(64) NOT NULL,
    event CHAR(64) DEFAULT 'presence' NOT NULL,
    event_id CHAR(64),
    to_tag CHAR(64) NOT NULL,
    from_tag CHAR(64) NOT NULL,
    callid CHAR(64) NOT NULL,
    local_cseq INTEGER NOT NULL,
    remote_cseq INTEGER NOT NULL,
    contact CHAR(64) NOT NULL,
    record_route TEXT,
    expires INTEGER NOT NULL,
    status INTEGER DEFAULT 2 NOT NULL,
    reason CHAR(64) NOT NULL,
    version INTEGER DEFAULT 0 NOT NULL,
    socket_info CHAR(64) NOT NULL,
    local_contact CHAR(255) NOT NULL,
    CONSTRAINT rls_watchers_rls_watcher_idx  UNIQUE (presentity_uri, callid, to_tag, from_tag)
);

