INSERT INTO version (table_name, table_version) values ('janus','1');
CREATE TABLE janus (
    id SERIAL PRIMARY KEY NOT NULL,
    janus_id TEXT NOT NULL,
    janus_url TEXT NOT NULL
);

ALTER SEQUENCE janus_id_seq MAXVALUE 2147483647 CYCLE;
