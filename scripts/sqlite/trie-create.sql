INSERT INTO version (table_name, table_version) values ('trie_table','1');
CREATE TABLE trie_table (
    ruleid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    prefix CHAR(64) NOT NULL,
    attrs CHAR(255) DEFAULT NULL,
    priority INTEGER DEFAULT 1 NOT NULL
);

INSERT INTO version (table_name, table_version) values ('dr_partitions','1');
CREATE TABLE dr_partitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    partition_name CHAR(255) NOT NULL,
    db_url CHAR(255) NOT NULL,
    trie_table CHAR(255)
);

