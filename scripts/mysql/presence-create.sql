INSERT INTO version (table_name, table_version) values ('presentity','5');
CREATE TABLE presentity (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    username CHAR(64) NOT NULL,
    domain CHAR(64) NOT NULL,
    event CHAR(64) NOT NULL,
    etag CHAR(64) NOT NULL,
    expires INT(11) NOT NULL,
    received_time INT(11) NOT NULL,
    body BLOB DEFAULT NULL,
    extra_hdrs BLOB DEFAULT NULL,
    sender CHAR(255) DEFAULT NULL,
    CONSTRAINT presentity_idx UNIQUE (username, domain, event, etag)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('active_watchers','12');
CREATE TABLE active_watchers (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
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
    local_cseq INT(11) NOT NULL,
    remote_cseq INT(11) NOT NULL,
    contact CHAR(255) NOT NULL,
    record_route TEXT,
    expires INT(11) NOT NULL,
    status INT(11) DEFAULT 2 NOT NULL,
    reason CHAR(64),
    version INT(11) DEFAULT 0 NOT NULL,
    socket_info CHAR(64) NOT NULL,
    local_contact CHAR(255) NOT NULL,
    sharing_tag CHAR(32) DEFAULT NULL,
    CONSTRAINT active_watchers_idx UNIQUE (presentity_uri, callid, to_tag, from_tag)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('watchers','4');
CREATE TABLE watchers (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    presentity_uri CHAR(255) NOT NULL,
    watcher_username CHAR(64) NOT NULL,
    watcher_domain CHAR(64) NOT NULL,
    event CHAR(64) DEFAULT 'presence' NOT NULL,
    status INT(11) NOT NULL,
    reason CHAR(64),
    inserted_time INT(11) NOT NULL,
    CONSTRAINT watcher_idx UNIQUE (presentity_uri, watcher_username, watcher_domain, event)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('xcap','4');
CREATE TABLE xcap (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    username CHAR(64) NOT NULL,
    domain CHAR(64) NOT NULL,
    doc LONGBLOB NOT NULL,
    doc_type INT(11) NOT NULL,
    etag CHAR(64) NOT NULL,
    source INT(11) NOT NULL,
    doc_uri CHAR(255) NOT NULL,
    port INT(11) NOT NULL,
    CONSTRAINT account_doc_type_idx UNIQUE (username, domain, doc_type, doc_uri)
) ENGINE=InnoDB;

CREATE INDEX source_idx ON xcap (source);

INSERT INTO version (table_name, table_version) values ('pua','8');
CREATE TABLE pua (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    pres_uri CHAR(255) NOT NULL,
    pres_id CHAR(255) NOT NULL,
    event INT(11) NOT NULL,
    expires INT(11) NOT NULL,
    desired_expires INT(11) NOT NULL,
    flag INT(11) NOT NULL,
    etag CHAR(64),
    tuple_id CHAR(64),
    watcher_uri CHAR(255),
    to_uri CHAR(255),
    call_id CHAR(64),
    to_tag CHAR(64),
    from_tag CHAR(64),
    cseq INT(11),
    record_route TEXT,
    contact CHAR(255),
    remote_contact CHAR(255),
    version INT(11),
    extra_headers TEXT
) ENGINE=InnoDB;

CREATE INDEX del1_idx ON pua (pres_uri, event);
CREATE INDEX del2_idx ON pua (expires);
CREATE INDEX update_idx ON pua (pres_uri, pres_id, flag, event);

