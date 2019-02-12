INSERT INTO version (table_name, table_version) values ('dialplan','5');
CREATE TABLE dialplan (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    dpid INTEGER NOT NULL,
    pr INTEGER DEFAULT 0 NOT NULL,
    match_op INTEGER NOT NULL,
    match_exp CHAR(64) NOT NULL,
    match_flags INTEGER DEFAULT 0 NOT NULL,
    subst_exp CHAR(64) DEFAULT NULL,
    repl_exp CHAR(32) DEFAULT NULL,
    timerec CHAR(255) DEFAULT NULL,
    disabled INTEGER DEFAULT 0 NOT NULL,
    attrs CHAR(255) DEFAULT NULL
);

