INSERT INTO version (table_name, table_version) values ('dialog','3');
CREATE TABLE dialog (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    hash_entry INT(10) UNSIGNED NOT NULL,
    hash_id INT(10) UNSIGNED NOT NULL,
    callid CHAR(255) NOT NULL,
    from_uri CHAR(128) NOT NULL,
    from_tag CHAR(64) NOT NULL,
    to_uri CHAR(128) NOT NULL,
    to_tag CHAR(64) NOT NULL,
    caller_cseq CHAR(7) NOT NULL,
    callee_cseq CHAR(7) NOT NULL,
    caller_route_set TEXT(512),
    callee_route_set TEXT(512),
    caller_contact CHAR(128) NOT NULL,
    callee_contact CHAR(128) NOT NULL,
    caller_sock CHAR(64) NOT NULL,
    callee_sock CHAR(64) NOT NULL,
    state INT(10) UNSIGNED NOT NULL,
    start_time INT(10) UNSIGNED NOT NULL,
    timeout INT(10) UNSIGNED NOT NULL
) ENGINE=MyISAM;

CREATE INDEX hash_idx ON dialog (hash_entry, hash_id);

