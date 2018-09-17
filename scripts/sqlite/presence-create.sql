INSERT INTO version (table_name, table_version) values ('presentity','5');
CREATE TABLE presentity (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username CHAR(64) NOT NULL,
    domain CHAR(64) NOT NULL,
    event CHAR(64) NOT NULL,
    etag CHAR(64) NOT NULL,
    expires INTEGER NOT NULL,
    received_time INTEGER NOT NULL,
    body BLOB DEFAULT NULL,
    extra_hdrs BLOB DEFAULT NULL,
    sender CHAR(255) DEFAULT NULL,
    CONSTRAINT presentity_presentity_idx  UNIQUE (username, domain, event, etag)
);

INSERT INTO version (table_name, table_version) values ('active_watchers','12');
CREATE TABLE active_watchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    presentity_uri CHAR(255) NOT NULL,
    watcher_username CHAR(64) NOT NULL,
    watcher_domain CHAR(64) NOT NULL,
    to_user CHAR(64) NOT NULL,
    to_domain CHAR(64) NOT NULL,
    event CHAR(64) DEFAULT 'presence' NOT NULL,
    event_id CHAR(64),
    to_tag CHAR(64) NOT NULL,
    from_tag CHAR(64) NOT NULL,
    callid CHAR(64) NOT NULL,
    local_cseq INTEGER NOT NULL,
    remote_cseq INTEGER NOT NULL,
    contact CHAR(255) NOT NULL,
    record_route TEXT,
    expires INTEGER NOT NULL,
    status INTEGER DEFAULT 2 NOT NULL,
    reason CHAR(64),
    version INTEGER DEFAULT 0 NOT NULL,
    socket_info CHAR(64) NOT NULL,
    local_contact CHAR(255) NOT NULL,
    sharing_tag CHAR(32) DEFAULT NULL,
    CONSTRAINT ORA_active_watchers_idx  UNIQUE (presentity_uri, callid, to_tag, from_tag)
);

INSERT INTO version (table_name, table_version) values ('watchers','4');
CREATE TABLE watchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    presentity_uri CHAR(255) NOT NULL,
    watcher_username CHAR(64) NOT NULL,
    watcher_domain CHAR(64) NOT NULL,
    event CHAR(64) DEFAULT 'presence' NOT NULL,
    status INTEGER NOT NULL,
    reason CHAR(64),
    inserted_time INTEGER NOT NULL,
    CONSTRAINT watchers_watcher_idx  UNIQUE (presentity_uri, watcher_username, watcher_domain, event)
);

INSERT INTO version (table_name, table_version) values ('xcap','4');
CREATE TABLE xcap (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username CHAR(64) NOT NULL,
    domain CHAR(64) NOT NULL,
    doc BLOB NOT NULL,
    doc_type INTEGER NOT NULL,
    etag CHAR(64) NOT NULL,
    source INTEGER NOT NULL,
    doc_uri CHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    CONSTRAINT xcap_account_doc_type_idx  UNIQUE (username, domain, doc_type, doc_uri)
);

CREATE INDEX xcap_source_idx  ON xcap (source);

INSERT INTO version (table_name, table_version) values ('pua','8');
CREATE TABLE pua (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    pres_uri CHAR(255) NOT NULL,
    pres_id CHAR(255) NOT NULL,
    event INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    desired_expires INTEGER NOT NULL,
    flag INTEGER NOT NULL,
    etag CHAR(64),
    tuple_id CHAR(64),
    watcher_uri CHAR(255),
    to_uri CHAR(255),
    call_id CHAR(64),
    to_tag CHAR(64),
    from_tag CHAR(64),
    cseq INTEGER,
    record_route TEXT,
    contact CHAR(255),
    remote_contact CHAR(255),
    version INTEGER,
    extra_headers TEXT
);

CREATE INDEX pua_del1_idx  ON pua (pres_uri, event);
CREATE INDEX pua_del2_idx  ON pua (expires);
CREATE INDEX pua_update_idx  ON pua (pres_uri, pres_id, flag, event);

