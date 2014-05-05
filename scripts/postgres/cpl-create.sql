INSERT INTO version (table_name, table_version) values ('cpl','2');
CREATE TABLE cpl (
    id SERIAL PRIMARY KEY NOT NULL,
    username VARCHAR(64) NOT NULL,
    domain VARCHAR(64) DEFAULT '' NOT NULL,
    cpl_xml TEXT,
    cpl_bin TEXT,
    CONSTRAINT cpl_account_idx UNIQUE (username, domain)
);

ALTER SEQUENCE cpl_id_seq MAXVALUE 2147483647 CYCLE;
