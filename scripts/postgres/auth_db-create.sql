INSERT INTO version (table_name, table_version) values ('subscriber','7');
CREATE TABLE subscriber (
    id SERIAL PRIMARY KEY NOT NULL,
    username VARCHAR(64) DEFAULT '' NOT NULL,
    domain VARCHAR(64) DEFAULT '' NOT NULL,
    password VARCHAR(25) DEFAULT '' NOT NULL,
    email_address VARCHAR(64) DEFAULT '' NOT NULL,
    ha1 VARCHAR(64) DEFAULT '' NOT NULL,
    ha1b VARCHAR(64) DEFAULT '' NOT NULL,
    rpid VARCHAR(64) DEFAULT NULL,
    CONSTRAINT subscriber_account_idx UNIQUE (username, domain)
);

ALTER SEQUENCE subscriber_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX subscriber_username_idx ON subscriber (username);

