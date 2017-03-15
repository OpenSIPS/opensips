INSERT INTO version (table_name, table_version) values ('dispatcher','8');
CREATE TABLE dispatcher (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    setid INTEGER DEFAULT 0 NOT NULL,
    destination CHAR(192) DEFAULT '' NOT NULL,
    socket CHAR(128) DEFAULT NULL,
    state INTEGER DEFAULT 0 NOT NULL,
    weight CHAR(64) DEFAULT 1 NOT NULL,
    priority INTEGER DEFAULT 0 NOT NULL,
    attrs CHAR(128) DEFAULT '' NOT NULL,
    description CHAR(64) DEFAULT '' NOT NULL
);

