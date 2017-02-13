INSERT INTO version (table_name, table_version) values ('dispatcher','8');
CREATE TABLE dispatcher (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    setid INT DEFAULT 0 NOT NULL,
    destination CHAR(192) DEFAULT '' NOT NULL,
    socket CHAR(128) DEFAULT NULL,
    state INT DEFAULT 0 NOT NULL,
    weight CHAR(64) DEFAULT 1 NOT NULL,
    priority INT DEFAULT 0 NOT NULL,
    attrs CHAR(128) DEFAULT '' NOT NULL,
    description CHAR(64) DEFAULT '' NOT NULL
) ENGINE=InnoDB;

