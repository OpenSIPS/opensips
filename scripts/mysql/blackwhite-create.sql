INSERT INTO version (table_name, table_version) values ('blackwhite','1');

CREATE TABLE blackwhite (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    username CHAR(64) NOT NULL,
    ip CHAR(50) NOT NULL,
    mask TINYINT DEFAULT 32 NOT NULL,
    flag TINYINT DEFAULT 0 NOT NULL
) ENGINE=MyISAM;
