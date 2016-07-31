INSERT INTO version (table_name, table_version) values ('clusterer','2');
CREATE TABLE clusterer (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    cluster_id INTEGER NOT NULL,
    node_id INTEGER NOT NULL,
    url CHAR(64) NOT NULL,
    state INTEGER DEFAULT 1 NOT NULL,
    ls_seq_no INTEGER DEFAULT 0 NOT NULL,
    top_seq_no INTEGER DEFAULT 0 NOT NULL,
    no_ping_retries INTEGER DEFAULT 3 NOT NULL,
    priority INTEGER DEFAULT 50 NOT NULL,
    sip_addr CHAR(64),
    description CHAR(64),
    CONSTRAINT clusterer_clusterer_idx  UNIQUE (cluster_id, node_id)
);

