INSERT INTO version (table_name, table_version) values ('janus','1');
CREATE TABLE janus (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    janus_id TEXT NOT NULL,
    janus_url TEXT NOT NULL
) ENGINE=InnoDB;

