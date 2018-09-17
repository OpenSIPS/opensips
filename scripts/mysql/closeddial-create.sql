INSERT INTO version (table_name, table_version) values ('closeddial','1');
CREATE TABLE closeddial (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    cd_username CHAR(64) DEFAULT '' NOT NULL,
    cd_domain CHAR(64) DEFAULT '' NOT NULL,
    group_id CHAR(64) DEFAULT '' NOT NULL,
    new_uri CHAR(255) DEFAULT '' NOT NULL,
    CONSTRAINT cd_idx1 UNIQUE (username, domain, cd_domain, cd_username, group_id)
) ENGINE=InnoDB;

CREATE INDEX cd_idx2 ON closeddial (group_id);
CREATE INDEX cd_idx3 ON closeddial (cd_username);
CREATE INDEX cd_idx4 ON closeddial (username);

