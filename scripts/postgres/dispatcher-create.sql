INSERT INTO version (table_name, table_version) values ('dispatcher','9');
CREATE TABLE dispatcher (
    id SERIAL PRIMARY KEY NOT NULL,
    setid INTEGER DEFAULT 0 NOT NULL,
    destination VARCHAR(192) DEFAULT '' NOT NULL,
    socket VARCHAR(128) DEFAULT NULL,
    state INTEGER DEFAULT 0 NOT NULL,
    probe_mode INTEGER DEFAULT 0 NOT NULL,
    weight VARCHAR(64) DEFAULT 1 NOT NULL,
    priority INTEGER DEFAULT 0 NOT NULL,
    attrs VARCHAR(128) DEFAULT NULL,
    description VARCHAR(64) DEFAULT NULL
);

ALTER SEQUENCE dispatcher_id_seq MAXVALUE 2147483647 CYCLE;
