INSERT INTO version (table_name, table_version) values ('usr_preferences','3');
CREATE TABLE usr_preferences (
    id SERIAL PRIMARY KEY NOT NULL,
    uuid VARCHAR(64) DEFAULT '' NOT NULL,
    username VARCHAR(64) DEFAULT 0 NOT NULL,
    domain VARCHAR(64) DEFAULT '' NOT NULL,
    attribute VARCHAR(32) DEFAULT '' NOT NULL,
    type INTEGER DEFAULT 0 NOT NULL,
    value VARCHAR(128) DEFAULT '' NOT NULL,
    last_modified TIMESTAMP WITHOUT TIME ZONE DEFAULT '1900-01-01 00:00:01' NOT NULL
);

ALTER SEQUENCE usr_preferences_id_seq MAXVALUE 2147483647 CYCLE;
CREATE INDEX usr_preferences_ua_idx ON usr_preferences (uuid, attribute);
CREATE INDEX usr_preferences_uda_idx ON usr_preferences (username, domain, attribute);
CREATE INDEX usr_preferences_value_idx ON usr_preferences (value);

