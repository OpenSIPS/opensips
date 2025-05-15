INSERT INTO version (table_name, table_version) values ('config','1');
CREATE TABLE config (
    id SERIAL PRIMARY KEY NOT NULL,
    name VARCHAR(255) NOT NULL,
    value TEXT DEFAULT NULL,
    description VARCHAR(255) DEFAULT NULL,
    CONSTRAINT config_name_idx UNIQUE (name)
);

ALTER SEQUENCE config_id_seq MAXVALUE 2147483647 CYCLE;
