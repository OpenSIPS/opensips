INSERT INTO version (table_name, table_version) values ('load_balancer','1');
CREATE TABLE load_balancer (
    id SERIAL PRIMARY KEY NOT NULL,
    group_id INTEGER DEFAULT 0 NOT NULL,
    dst_uri VARCHAR(128) NOT NULL,
    resources VARCHAR(255) NOT NULL,
    description VARCHAR(128) DEFAULT '' NOT NULL
);

CREATE INDEX load_balancer_dsturi_idx ON load_balancer (dst_uri);

