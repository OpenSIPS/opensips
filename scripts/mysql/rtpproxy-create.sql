INSERT INTO version (table_name, table_version) values ('rtpproxy_sockets','0');
CREATE TABLE rtpproxy_sockets (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    rtpproxy_sock TEXT NOT NULL,
    set_id INT(10) UNSIGNED NOT NULL
) ENGINE=InnoDB;

