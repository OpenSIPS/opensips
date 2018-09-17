INSERT INTO version (table_name, table_version) values ('rls_presentity','1');
CREATE TABLE rls_presentity (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    rlsubs_did CHAR(255) NOT NULL,
    resource_uri CHAR(255) NOT NULL,
    content_type CHAR(255) NOT NULL,
    presence_state BLOB NOT NULL,
    expires INT(11) NOT NULL,
    updated INT(11) NOT NULL,
    auth_state INT(11) NOT NULL,
    reason CHAR(64) NOT NULL,
    CONSTRAINT rls_presentity_idx UNIQUE (rlsubs_did, resource_uri)
) ENGINE=InnoDB;

CREATE INDEX updated_idx ON rls_presentity (updated);

INSERT INTO version (table_name, table_version) values ('rls_watchers','2');
CREATE TABLE rls_watchers (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
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
    local_cseq INT(11) NOT NULL,
    remote_cseq INT(11) NOT NULL,
    contact CHAR(64) NOT NULL,
    record_route TEXT,
    expires INT(11) NOT NULL,
    status INT(11) DEFAULT 2 NOT NULL,
    reason CHAR(64) NOT NULL,
    version INT(11) DEFAULT 0 NOT NULL,
    socket_info CHAR(64) NOT NULL,
    local_contact CHAR(255) NOT NULL,
    CONSTRAINT rls_watcher_idx UNIQUE (presentity_uri, callid, to_tag, from_tag)
) ENGINE=InnoDB;

