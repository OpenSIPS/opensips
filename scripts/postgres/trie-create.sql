INSERT INTO version (table_name, table_version) values ('trie_table','1');
CREATE TABLE trie_table (
    ruleid SERIAL PRIMARY KEY NOT NULL,
    prefix VARCHAR(64) NOT NULL,
    attrs VARCHAR(255) DEFAULT NULL,
    priority INTEGER DEFAULT 1 NOT NULL
);

ALTER SEQUENCE trie_table_ruleid_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('dr_partitions','1');
CREATE TABLE dr_partitions (
    id SERIAL PRIMARY KEY NOT NULL,
    partition_name VARCHAR(255) NOT NULL,
    db_url VARCHAR(255) NOT NULL,
    trie_table VARCHAR(255)
);

ALTER SEQUENCE dr_partitions_id_seq MAXVALUE 2147483647 CYCLE;
