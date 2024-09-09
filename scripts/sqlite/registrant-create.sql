INSERT INTO version (table_name, table_version) values ('registrant','3');
CREATE TABLE registrant (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    registrar CHAR(255) DEFAULT '' NOT NULL,
    proxy CHAR(255) DEFAULT NULL,
    aor CHAR(255) DEFAULT '' NOT NULL,
    third_party_registrant CHAR(255) DEFAULT NULL,
    username CHAR(64) DEFAULT NULL,
    password CHAR(64) DEFAULT NULL,
    binding_URI CHAR(255) DEFAULT '' NOT NULL,
    binding_params CHAR(64) DEFAULT NULL,
    expiry INTEGER DEFAULT NULL,
    forced_socket CHAR(64) DEFAULT NULL,
    cluster_shtag CHAR(64) DEFAULT NULL,
    state INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT registrant_registrant_idx  UNIQUE (aor, binding_URI, registrar)
);

