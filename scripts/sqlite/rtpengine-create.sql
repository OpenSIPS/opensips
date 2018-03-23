INSERT INTO version (table_name, table_version) values ('rtpengine','1');
CREATE TABLE rtpengine (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    socket TEXT NOT NULL,
    set_id INTEGER NOT NULL
);

