INSERT INTO version (table_name, table_version) values ('nh_sockets','0');
CREATE TABLE nh_sockets (
    id SERIAL PRIMARY KEY NOT NULL,
    rtpproxy_sock TEXT NOT NULL,
    set_id INTEGER NOT NULL
);

