INSERT INTO version (table_name, table_version) values ('clusterer','1');
CREATE TABLE clusterer (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    cluster_id INTEGER NOT NULL,
    machine_id INTEGER NOT NULL,
    url CHAR(64) NOT NULL,
    state INTEGER DEFAULT 1 NOT NULL,
    last_attempt BIGINT(64) DEFAULT 0 NOT NULL,
    failed_attempts INTEGER DEFAULT 3 NOT NULL,
    no_tries INTEGER DEFAULT 0 NOT NULL,
    duration INTEGER DEFAULT 30 NOT NULL,
    description CHAR(64),
    CONSTRAINT clusterer_clusterer_idx  UNIQUE (cluster_id, machine_id)
);

