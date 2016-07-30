INSERT INTO version (table_name, table_version) values ('dialplan','5');
CREATE TABLE dialplan (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    dpid INTEGER NOT NULL,
    pr INTEGER NOT NULL,
    match_op INTEGER NOT NULL,
    match_exp CHAR(64) NOT NULL,
    match_flags INTEGER NOT NULL,
    subst_exp CHAR(64),
    repl_exp CHAR(32),
    timerec CHAR(255),
    disabled INTEGER DEFAULT 0 NOT NULL,
    attrs CHAR(32)
);

