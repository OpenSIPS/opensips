INSERT INTO version (table_name, table_version) values ('usr_preferences','3');
CREATE TABLE usr_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    uuid CHAR(64) DEFAULT '' NOT NULL,
    username CHAR(64) DEFAULT 0 NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    attribute CHAR(32) DEFAULT '' NOT NULL,
    type INTEGER DEFAULT 0 NOT NULL,
    value CHAR(128) DEFAULT '' NOT NULL,
    last_modified DATETIME DEFAULT '1900-01-01 00:00:01' NOT NULL
);

CREATE INDEX usr_preferences_ua_idx  ON usr_preferences (uuid, attribute);
CREATE INDEX usr_preferences_uda_idx  ON usr_preferences (username, domain, attribute);
CREATE INDEX usr_preferences_value_idx  ON usr_preferences (value);

