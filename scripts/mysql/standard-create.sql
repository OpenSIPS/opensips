CREATE TABLE version (
    table_name VARCHAR(32) NOT NULL,
    table_version INT UNSIGNED DEFAULT 0 NOT NULL,
    CONSTRAINT t_name_idx UNIQUE (table_name)
) ENGINE=MyISAM;

