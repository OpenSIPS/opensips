INSERT INTO version (table_name, table_version) values ('sockets','1');
CREATE TABLE sockets (
    id SERIAL PRIMARY KEY NOT NULL,
    socket VARCHAR(128) NOT NULL,
    advertised VARCHAR(128) DEFAULT NULL,
    tag VARCHAR(128) DEFAULT NULL,
    flags VARCHAR(128) DEFAULT NULL,
    tos VARCHAR(32) DEFAULT NULL
);

ALTER SEQUENCE sockets_id_seq MAXVALUE 2147483647 CYCLE;
