INSERT INTO version (table_name, table_version) values ('clusterer','1');
CREATE TABLE clusterer (
    id INT(10) AUTO_INCREMENT PRIMARY KEY NOT NULL,
    cluster_id INT(10) NOT NULL,
    machine_id INT(10) NOT NULL,
    url CHAR(64) NOT NULL,
    state INT(1) DEFAULT 1 NOT NULL,
    last_attempt BIGINT(64) UNSIGNED DEFAULT 0 NOT NULL,
    failed_attempts INT(10) DEFAULT 3 NOT NULL,
    no_tries INT(10) DEFAULT 0 NOT NULL,
    duration INT(10) DEFAULT 30 NOT NULL,
    description CHAR(64),
    CONSTRAINT clusterer_idx UNIQUE (cluster_id, machine_id)
) ENGINE=InnoDB;

