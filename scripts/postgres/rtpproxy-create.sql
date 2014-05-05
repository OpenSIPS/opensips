INSERT INTO version (table_name, table_version) values ('rtpproxy_sockets','0');
CREATE TABLE rtpproxy_sockets (
    id SERIAL PRIMARY KEY NOT NULL,
    rtpproxy_sock TEXT NOT NULL,
    set_id INTEGER NOT NULL
);

ALTER SEQUENCE rtpproxy_sockets_id_seq MAXVALUE 2147483647 CYCLE;
