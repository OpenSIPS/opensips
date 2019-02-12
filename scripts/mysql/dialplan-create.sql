INSERT INTO version (table_name, table_version) values ('dialplan','5');
CREATE TABLE dialplan (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    dpid INT(11) NOT NULL,
    pr INT(11) DEFAULT 0 NOT NULL,
    match_op INT(11) NOT NULL,
    match_exp CHAR(64) NOT NULL,
    match_flags INT(11) DEFAULT 0 NOT NULL,
    subst_exp CHAR(64) DEFAULT NULL,
    repl_exp CHAR(32) DEFAULT NULL,
    timerec CHAR(255) DEFAULT NULL,
    disabled INT(11) DEFAULT 0 NOT NULL,
    attrs CHAR(255) DEFAULT NULL
) ENGINE=InnoDB;

