INSERT INTO version (table_name, table_version) values ('clusterer','2');
CREATE TABLE clusterer (
    id INT(10) AUTO_INCREMENT PRIMARY KEY NOT NULL,
    cluster_id INT(10) NOT NULL,
    node_id INT(10) NOT NULL,
    url CHAR(64) NOT NULL,
    state INT(1) DEFAULT 1 NOT NULL,
    ls_seq_no INT(10) DEFAULT 0 NOT NULL,
    top_seq_no INT(10) DEFAULT 0 NOT NULL,
    no_ping_retries INT(10) DEFAULT 3 NOT NULL,
    priority INT(10) DEFAULT 50 NOT NULL,
    sip_addr CHAR(64),
    description CHAR(64),
    CONSTRAINT clusterer_idx UNIQUE (cluster_id, node_id)
) ENGINE=InnoDB;

