INSERT INTO version (table_name, table_version) values ('sockets','1');
CREATE TABLE sockets (
    id SERIAL PRIMARY KEY NOT NULL,
    socket VARCHAR(128) NOT NULL,
    pool VARCHAR(128) DEFAULT NULL
);

ALTER SEQUENCE sockets_id_seq MAXVALUE 2147483647 CYCLE;
