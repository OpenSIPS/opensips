INSERT INTO version (table_name, table_version) values ('trie_table','1');
CREATE TABLE trie_table (
    ruleid NUMBER(10) PRIMARY KEY,
    prefix VARCHAR2(64),
    attrs VARCHAR2(255) DEFAULT NULL,
    enabled NUMBER(10) DEFAULT 1 NOT NULL
);

CREATE OR REPLACE TRIGGER trie_table_tr
before insert on trie_table FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END trie_table_tr;
/
BEGIN map2users('trie_table'); END;
/
INSERT INTO version (table_name, table_version) values ('trie_partitions','1');
CREATE TABLE trie_partitions (
    id NUMBER(10) PRIMARY KEY,
    partition_name VARCHAR2(255),
    db_url VARCHAR2(255),
    trie_table VARCHAR2(255)
);

CREATE OR REPLACE TRIGGER trie_partitions_tr
before insert on trie_partitions FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END trie_partitions_tr;
/
BEGIN map2users('trie_partitions'); END;
/
