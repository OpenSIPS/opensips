INSERT INTO version (table_name, table_version) values ('freeswitch','1');
CREATE TABLE freeswitch (
    id SERIAL PRIMARY KEY NOT NULL,
    username VARCHAR(64),
    password VARCHAR(64) NOT NULL,
    ip VARCHAR(20) NOT NULL,
    port INTEGER DEFAULT 8021 NOT NULL,
    events_csv VARCHAR(255)
);

ALTER SEQUENCE freeswitch_id_seq MAXVALUE 2147483647 CYCLE;
