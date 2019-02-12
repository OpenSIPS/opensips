INSERT INTO version (table_name, table_version) values ('dialplan','5');
CREATE TABLE dialplan (
    id NUMBER(10) PRIMARY KEY,
    dpid NUMBER(10),
    pr NUMBER(10) DEFAULT 0 NOT NULL,
    match_op NUMBER(10),
    match_exp VARCHAR2(64),
    match_flags NUMBER(10) DEFAULT 0 NOT NULL,
    subst_exp VARCHAR2(64) DEFAULT NULL,
    repl_exp VARCHAR2(32) DEFAULT NULL,
    timerec VARCHAR2(255) DEFAULT NULL,
    disabled NUMBER(10) DEFAULT 0 NOT NULL,
    attrs VARCHAR2(255) DEFAULT NULL
);

CREATE OR REPLACE TRIGGER dialplan_tr
before insert on dialplan FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END dialplan_tr;
/
BEGIN map2users('dialplan'); END;
/
