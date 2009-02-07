INSERT INTO version (table_name, table_version) values ('dialplan','2');
CREATE TABLE dialplan (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    dpid INT(11) NOT NULL,
    pr INT(11) NOT NULL,
    match_op INT(11) NOT NULL,
    match_exp CHAR(64) NOT NULL,
    match_len INT(11) NOT NULL,
    subst_exp CHAR(64) NOT NULL,
    repl_exp CHAR(32) NOT NULL,
    attrs CHAR(32) NOT NULL
) ENGINE=MyISAM;

