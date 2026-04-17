INSERT INTO version (table_name, table_version) values ('clusterer','4');
CREATE TABLE clusterer (
    id INT(10) AUTO_INCREMENT PRIMARY KEY NOT NULL,
    cluster_id INT(10) NOT NULL,
    node_id INT(10) NOT NULL,
    url CHAR(64) NOT NULL,
    state INT(1) DEFAULT 1 NOT NULL,
    no_ping_retries INT(10) DEFAULT 3 NOT NULL,
    priority INT(10) DEFAULT 50 NOT NULL,
    sip_addr CHAR(64),
    flags CHAR(64),
    description CHAR(64),
    CONSTRAINT clusterer_idx UNIQUE (cluster_id, node_id)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('clusterer_bridge','1');
CREATE TABLE clusterer_bridge (
    id INT(10) AUTO_INCREMENT PRIMARY KEY NOT NULL,
    cluster_a INT(10) NOT NULL,
    cluster_b INT(10) NOT NULL,
    send_shtag CHAR(32) NOT NULL,
    dst_node_csv TEXT,
    CONSTRAINT clusterer_bridge_idx UNIQUE (cluster_a, cluster_b)
) ENGINE=InnoDB;

