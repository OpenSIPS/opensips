INSERT INTO version (table_name, table_version) values ('registrant','1');
CREATE TABLE registrant (
    id SERIAL PRIMARY KEY NOT NULL,
    registrar VARCHAR(128) DEFAULT '' NOT NULL,
    proxy VARCHAR(128) DEFAULT NULL,
    aor VARCHAR(128) DEFAULT '' NOT NULL,
    third_party_registrant VARCHAR(128) DEFAULT NULL,
    username VARCHAR(64) DEFAULT NULL,
    password VARCHAR(64) DEFAULT NULL,
    binding_URI VARCHAR(128) DEFAULT '' NOT NULL,
    binding_params VARCHAR(64) DEFAULT NULL,
    expiry INTEGER DEFAULT NULL,
    forced_socket VARCHAR(64) DEFAULT NULL,
    CONSTRAINT registrant_aor_idx UNIQUE (aor)
);

ALTER SEQUENCE registrant_id_seq MAXVALUE 2147483647 CYCLE;
