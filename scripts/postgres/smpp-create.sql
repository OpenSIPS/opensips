INSERT INTO version (table_name, table_version) values ('smpp','1');
CREATE TABLE smpp (
    id SERIAL PRIMARY KEY NOT NULL,
    name VARCHAR(255) NOT NULL,
    ip VARCHAR(50) NOT NULL,
    port INTEGER NOT NULL,
    system_id VARCHAR(16) NOT NULL,
    password VARCHAR(9) NOT NULL,
    system_type VARCHAR(13) DEFAULT '' NOT NULL,
    src_ton INTEGER DEFAULT 0 NOT NULL,
    src_npi INTEGER DEFAULT 0 NOT NULL,
    dst_ton INTEGER DEFAULT 0 NOT NULL,
    dst_npi INTEGER DEFAULT 0 NOT NULL,
    session_type INTEGER DEFAULT 1 NOT NULL,
    CONSTRAINT smpp_unique_name UNIQUE (name)
);

ALTER SEQUENCE smpp_id_seq MAXVALUE 2147483647 CYCLE;
