INSERT INTO version (table_name, table_version) values ('sip_trace','3');
CREATE TABLE sip_trace (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    time_stamp DATETIME DEFAULT '1900-01-01 00:00:01' NOT NULL,
    callid CHAR(255) DEFAULT '' NOT NULL,
    traced_user CHAR(128) DEFAULT NULL,
    msg TEXT NOT NULL,
    method CHAR(32) DEFAULT '' NOT NULL,
    status CHAR(128) DEFAULT NULL,
    fromip CHAR(50) DEFAULT '' NOT NULL,
    toip CHAR(50) DEFAULT '' NOT NULL,
    fromtag CHAR(64) DEFAULT '' NOT NULL,
    direction CHAR(4) DEFAULT '' NOT NULL
) ENGINE=MyISAM;

CREATE INDEX traced_user_idx ON sip_trace (traced_user);
CREATE INDEX date_idx ON sip_trace (time_stamp);
CREATE INDEX fromip_idx ON sip_trace (fromip);
CREATE INDEX callid_idx ON sip_trace (callid);

