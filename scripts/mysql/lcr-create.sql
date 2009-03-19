INSERT INTO version (table_name, table_version) values ('gw','8');
CREATE TABLE gw (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    gw_name CHAR(128) NOT NULL,
    grp_id INT UNSIGNED NOT NULL,
    ip_addr CHAR(15) NOT NULL,
    port SMALLINT UNSIGNED,
    uri_scheme TINYINT UNSIGNED,
    transport TINYINT UNSIGNED,
    strip TINYINT UNSIGNED,
    tag CHAR(16) DEFAULT NULL,
    flags INT UNSIGNED DEFAULT 0 NOT NULL,
    CONSTRAINT gw_name_idx UNIQUE (gw_name)
) ENGINE=MyISAM;

CREATE INDEX grp_id_idx ON gw (grp_id);

INSERT INTO version (table_name, table_version) values ('lcr','3');
CREATE TABLE lcr (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    prefix CHAR(16) DEFAULT NULL,
    from_uri CHAR(64) DEFAULT NULL,
    grp_id INT UNSIGNED NOT NULL,
    priority INT UNSIGNED NOT NULL
) ENGINE=MyISAM;

CREATE INDEX prefix_idx ON lcr (prefix);
CREATE INDEX from_uri_idx ON lcr (from_uri);
CREATE INDEX grp_id_idx ON lcr (grp_id);

