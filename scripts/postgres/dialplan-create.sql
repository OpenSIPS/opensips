INSERT INTO version (table_name, table_version) values ('dialplan','4');
CREATE TABLE dialplan (
    id SERIAL PRIMARY KEY NOT NULL,
    dpid INTEGER NOT NULL,
    pr INTEGER NOT NULL,
    match_op INTEGER NOT NULL,
    match_exp VARCHAR(64) NOT NULL,
    match_flags INTEGER NOT NULL,
    subst_exp VARCHAR(64),
    repl_exp VARCHAR(32),
    disabled INTEGER DEFAULT 0 NOT NULL,
    attrs VARCHAR(32)
);

ALTER SEQUENCE dialplan_id_seq MAXVALUE 2147483647 CYCLE;
