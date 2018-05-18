INSERT INTO version (table_name, table_version) values ('rc_clients','1');
CREATE TABLE rc_clients (
    id SERIAL PRIMARY KEY NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    wholesale_rate INTEGER DEFAULT 0 NOT NULL,
    retail_rate INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT rc_clients_client_id_idx UNIQUE (client_id)
);

ALTER SEQUENCE rc_clients_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('rc_vendors','1');
CREATE TABLE rc_vendors (
    id SERIAL PRIMARY KEY NOT NULL,
    vendor_id VARCHAR(64) NOT NULL,
    vendor_rate INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT rc_vendors_vendor_id_idx UNIQUE (vendor_id)
);

ALTER SEQUENCE rc_vendors_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('rc_ratesheets','1');
CREATE TABLE rc_ratesheets (
    id SERIAL PRIMARY KEY NOT NULL,
    ratesheet_table VARCHAR(64) NOT NULL,
    currency VARCHAR(64) NOT NULL,
    CONSTRAINT rc_ratesheets_table_idx UNIQUE (ratesheet_table)
);

ALTER SEQUENCE rc_ratesheets_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('rc_demo_ratesheet','1');
CREATE TABLE rc_demo_ratesheet (
    id SERIAL PRIMARY KEY NOT NULL,
    prefix VARCHAR(64) NOT NULL,
    destination VARCHAR(128) NOT NULL,
    price REAL DEFAULT 0 NOT NULL,
    minimum INTEGER DEFAULT 0 NOT NULL,
    increment INTEGER DEFAULT 1 NOT NULL,
    CONSTRAINT rc_demo_ratesheet_prefix_idx UNIQUE (prefix)
);

ALTER SEQUENCE rc_demo_ratesheet_id_seq MAXVALUE 2147483647 CYCLE;
