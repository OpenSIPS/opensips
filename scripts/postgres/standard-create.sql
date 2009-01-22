CREATE TABLE version (
    table_name VARCHAR(32) NOT NULL,
    table_version INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT version_t_name_idx UNIQUE (table_name)
);

