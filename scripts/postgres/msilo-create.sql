INSERT INTO version (table_name, table_version) values ('silo','6');
CREATE TABLE silo (
    id SERIAL PRIMARY KEY NOT NULL,
    src_addr VARCHAR(255) DEFAULT '' NOT NULL,
    dst_addr VARCHAR(255) DEFAULT '' NOT NULL,
    username VARCHAR(64) DEFAULT '' NOT NULL,
    domain VARCHAR(64) DEFAULT '' NOT NULL,
    inc_time INTEGER DEFAULT 0 NOT NULL,
    exp_time INTEGER DEFAULT 0 NOT NULL,
    snd_time INTEGER DEFAULT 0 NOT NULL,
    ctype VARCHAR(255) DEFAULT NULL,
    body BYTEA DEFAULT NULL
);

ALTER SEQUENCE silo_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX silo_account_idx ON silo (username, domain);

