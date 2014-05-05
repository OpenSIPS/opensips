INSERT INTO version (table_name, table_version) values ('dbaliases','2');
CREATE TABLE dbaliases (
    id SERIAL PRIMARY KEY NOT NULL,
    alias_username VARCHAR(64) DEFAULT '' NOT NULL,
    alias_domain VARCHAR(64) DEFAULT '' NOT NULL,
    username VARCHAR(64) DEFAULT '' NOT NULL,
    domain VARCHAR(64) DEFAULT '' NOT NULL,
    CONSTRAINT dbaliases_alias_idx UNIQUE (alias_username, alias_domain)
);

ALTER SEQUENCE dbaliases_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX dbaliases_target_idx ON dbaliases (username, domain);

