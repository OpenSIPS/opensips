INSERT INTO version (table_name, table_version) values ('pdt','2');
CREATE TABLE pdt (
    id SERIAL PRIMARY KEY NOT NULL,
    sdomain VARCHAR(128) NOT NULL,
    prefix VARCHAR(32) NOT NULL,
    domain VARCHAR(128) DEFAULT '' NOT NULL,
    CONSTRAINT pdt_sdomain_prefix_idx UNIQUE (sdomain, prefix)
);

ALTER SEQUENCE pdt_id_seq MAXVALUE 2147483647 CYCLE;
