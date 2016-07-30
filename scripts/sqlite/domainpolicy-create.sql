INSERT INTO version (table_name, table_version) values ('domainpolicy','3');
CREATE TABLE domainpolicy (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    rule CHAR(255) NOT NULL,
    type CHAR(255) NOT NULL,
    att CHAR(255),
    val CHAR(128),
    description CHAR(255) NOT NULL,
    CONSTRAINT domainpolicy_rav_idx  UNIQUE (rule, att, val)
);

CREATE INDEX domainpolicy_rule_idx  ON domainpolicy (rule);

