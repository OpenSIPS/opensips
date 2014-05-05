INSERT INTO version (table_name, table_version) values ('dispatcher','6');
CREATE TABLE dispatcher (
    id SERIAL PRIMARY KEY NOT NULL,
    setid INTEGER DEFAULT 0 NOT NULL,
    destination VARCHAR(192) DEFAULT '' NOT NULL,
    socket VARCHAR(128) DEFAULT NULL,
    state INTEGER DEFAULT 0 NOT NULL,
    weight INTEGER DEFAULT 1 NOT NULL,
    attrs VARCHAR(128) DEFAULT '' NOT NULL,
    description VARCHAR(64) DEFAULT '' NOT NULL
);

ALTER SEQUENCE dispatcher_id_seq MAXVALUE 2147483647 CYCLE;
