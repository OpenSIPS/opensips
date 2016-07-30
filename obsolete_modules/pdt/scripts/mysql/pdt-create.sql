INSERT INTO version (table_name, table_version) values ('pdt','2');
CREATE TABLE pdt (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    sdomain CHAR(128) NOT NULL,
    prefix CHAR(32) NOT NULL,
    domain CHAR(128) DEFAULT '' NOT NULL,
    CONSTRAINT sdomain_prefix_idx UNIQUE (sdomain, prefix)
) ENGINE=MyISAM;

