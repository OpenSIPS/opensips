INSERT INTO version (table_name, table_version) values ('silo','6');
CREATE TABLE silo (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    src_addr CHAR(128) DEFAULT '' NOT NULL,
    dst_addr CHAR(128) DEFAULT '' NOT NULL,
    username CHAR(64) DEFAULT '' NOT NULL,
    domain CHAR(64) DEFAULT '' NOT NULL,
    inc_time INT DEFAULT 0 NOT NULL,
    exp_time INT DEFAULT 0 NOT NULL,
    snd_time INT DEFAULT 0 NOT NULL,
    ctype CHAR(32) DEFAULT 'text/plain' NOT NULL,
    body BLOB DEFAULT '' NOT NULL
) ENGINE=MyISAM;

CREATE INDEX account_idx ON silo (username, domain);

