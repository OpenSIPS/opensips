INSERT INTO version (table_name, table_version) values ('clusterer','1');
CREATE TABLE clusterer (
    id SERIAL PRIMARY KEY NOT NULL,
    cluster_id INTEGER NOT NULL,
    machine_id INTEGER NOT NULL,
    url VARCHAR(64) NOT NULL,
    state INTEGER DEFAULT 1 NOT NULL,
    last_attempt BIGINT DEFAULT 0 NOT NULL,
    failed_attempts INTEGER DEFAULT 3 NOT NULL,
    no_tries INTEGER DEFAULT 0 NOT NULL,
    duration INTEGER DEFAULT 30 NOT NULL,
    description VARCHAR(64),
    CONSTRAINT clusterer_clusterer_idx UNIQUE (cluster_id, machine_id)
);

ALTER SEQUENCE clusterer_id_seq MAXVALUE 2147483647 CYCLE;
