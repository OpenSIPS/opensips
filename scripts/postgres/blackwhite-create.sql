INSERT INTO version (table_name, table_version) values ('blackwhite','1');

CREATE TABLE blackwhite (
    id SERIAL PRIMARY KEY NOT NULL,
    username VARCHAR(64) NOT NULL,
    ip VARCHAR(50) NOT NULL,
    mask SMALLINT DEFAULT 32 NOT NULL,
    flag SMALLINT DEFAULT 0 NOT NULL
);
