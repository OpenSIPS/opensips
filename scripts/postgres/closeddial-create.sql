INSERT INTO version (table_name, table_version) values ('closeddial','1');
CREATE TABLE closeddial (
    id SERIAL PRIMARY KEY NOT NULL,
    username VARCHAR(64) DEFAULT '' NOT NULL,
    domain VARCHAR(64) DEFAULT '' NOT NULL,
    cd_username VARCHAR(64) DEFAULT '' NOT NULL,
    cd_domain VARCHAR(64) DEFAULT '' NOT NULL,
    group_id VARCHAR(64) DEFAULT '' NOT NULL,
    new_uri VARCHAR(255) DEFAULT '' NOT NULL,
    CONSTRAINT closeddial_cd_idx1 UNIQUE (username, domain, cd_domain, cd_username, group_id)
);

ALTER SEQUENCE closeddial_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX closeddial_cd_idx2 ON closeddial (group_id);
CREATE INDEX closeddial_cd_idx3 ON closeddial (cd_username);
CREATE INDEX closeddial_cd_idx4 ON closeddial (username);

