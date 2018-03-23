INSERT INTO version (table_name, table_version) values ('rtpengine','1');
CREATE TABLE rtpengine (
    id SERIAL PRIMARY KEY NOT NULL,
    socket TEXT NOT NULL,
    set_id INTEGER NOT NULL
);

ALTER SEQUENCE rtpengine_id_seq MAXVALUE 2147483647 CYCLE;
