INSERT INTO version (table_name, table_version) values ('load_balancer','3');
CREATE TABLE load_balancer (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    group_id INTEGER DEFAULT 0 NOT NULL,
    dst_uri CHAR(128) NOT NULL,
    resources CHAR(255) NOT NULL,
    probe_mode INTEGER DEFAULT 0 NOT NULL,
    attrs CHAR(255) DEFAULT NULL,
    description CHAR(128) DEFAULT NULL
);

CREATE INDEX load_balancer_dsturi_idx  ON load_balancer (dst_uri);

