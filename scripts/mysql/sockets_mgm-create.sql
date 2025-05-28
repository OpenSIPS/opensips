INSERT INTO version (table_name, table_version) values ('sockets','1');
CREATE TABLE sockets (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    socket CHAR(128) NOT NULL,
    advertised CHAR(128) DEFAULT NULL,
    tag CHAR(128) DEFAULT NULL,
    flags CHAR(128) DEFAULT NULL,
    tos CHAR(32) DEFAULT NULL
) ENGINE=InnoDB;

