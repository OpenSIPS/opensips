INSERT INTO version (table_name, table_version) values ('janus','1');
CREATE TABLE janus (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    janus_id TEXT NOT NULL,
    janus_url TEXT NOT NULL
);

