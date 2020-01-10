INSERT INTO version (table_name, table_version) values ('load_balancer','3');
CREATE TABLE load_balancer (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    group_id INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    dst_uri CHAR(128) NOT NULL,
    resources CHAR(255) NOT NULL,
    probe_mode INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    attrs CHAR(255) DEFAULT NULL,
    description CHAR(128) DEFAULT NULL
) ENGINE=InnoDB;

CREATE INDEX dsturi_idx ON load_balancer (dst_uri);

