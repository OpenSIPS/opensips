INSERT INTO version (table_name, table_version) values ('clusterer','4');
CREATE TABLE clusterer (
    id SERIAL PRIMARY KEY NOT NULL,
    cluster_id INTEGER NOT NULL,
    node_id INTEGER NOT NULL,
    url VARCHAR(64) NOT NULL,
    state INTEGER DEFAULT 1 NOT NULL,
    no_ping_retries INTEGER DEFAULT 3 NOT NULL,
    priority INTEGER DEFAULT 50 NOT NULL,
    sip_addr VARCHAR(64),
    flags VARCHAR(64),
    description VARCHAR(64),
    CONSTRAINT clusterer_clusterer_idx UNIQUE (cluster_id, node_id)
);

ALTER SEQUENCE clusterer_id_seq MAXVALUE 2147483647 CYCLE;
