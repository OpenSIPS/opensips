INSERT INTO version (table_name, table_version) values ('rtpengine','1');
CREATE TABLE rtpengine (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    socket TEXT NOT NULL,
    set_id INT(10) UNSIGNED NOT NULL
) ENGINE=InnoDB;

