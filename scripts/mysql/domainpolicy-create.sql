INSERT INTO version (table_name, table_version) values ('domainpolicy','3');
CREATE TABLE domainpolicy (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    rule CHAR(255) NOT NULL,
    type CHAR(255) NOT NULL,
    att CHAR(255),
    val CHAR(128),
    description CHAR(255) NOT NULL,
    CONSTRAINT rav_idx UNIQUE (rule, att, val)
) ENGINE=InnoDB;

CREATE INDEX rule_idx ON domainpolicy (rule);

