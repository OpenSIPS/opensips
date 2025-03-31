INSERT INTO version (table_name, table_version) values ('trie_table','1');
CREATE TABLE trie_table (
    ruleid INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    prefix CHAR(64) NOT NULL,
    attrs CHAR(255) DEFAULT NULL,
    priority INT(11) DEFAULT 1 NOT NULL
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('dr_partitions','1');
CREATE TABLE dr_partitions (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    partition_name CHAR(255) NOT NULL,
    db_url CHAR(255) NOT NULL,
    trie_table CHAR(255)
) ENGINE=InnoDB;

