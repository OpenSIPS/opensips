INSERT INTO version (table_name, table_version) values ('dispatcher','4');
CREATE TABLE dispatcher (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    setid INT DEFAULT 0 NOT NULL,
    destination CHAR(192) DEFAULT '' NOT NULL,
    flags INT DEFAULT 0 NOT NULL,
    weight INT DEFAULT 1 NOT NULL,
    attrs CHAR(128) DEFAULT '' NOT NULL,
    description CHAR(64) DEFAULT '' NOT NULL
) ENGINE=MyISAM;

