INSERT INTO version (table_name, table_version) values ('userblacklist','2');
CREATE TABLE userblacklist (
    id SERIAL PRIMARY KEY NOT NULL,
    username VARCHAR(64) DEFAULT '' NOT NULL,
    domain VARCHAR(64) DEFAULT '' NOT NULL,
    prefix VARCHAR(64) DEFAULT '' NOT NULL,
    whitelist SMALLINT DEFAULT 0 NOT NULL
);

ALTER SEQUENCE userblacklist_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX userblacklist_userblacklist_idx ON userblacklist (username, domain, prefix);

INSERT INTO version (table_name, table_version) values ('globalblacklist','2');
CREATE TABLE globalblacklist (
    id SERIAL PRIMARY KEY NOT NULL,
    prefix VARCHAR(64) DEFAULT '' NOT NULL,
    whitelist SMALLINT DEFAULT 0 NOT NULL,
    description VARCHAR(255) DEFAULT NULL
);

ALTER SEQUENCE globalblacklist_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX globalblacklist_globalblacklist_idx ON globalblacklist (prefix);

