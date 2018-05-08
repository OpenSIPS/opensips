INSERT INTO version (table_name, table_version) values ('rc_accounts','1');
CREATE TABLE rc_accounts (
    id SERIAL PRIMARY KEY NOT NULL,
    account_id VARCHAR(64) NOT NULL,
    wholesale_rate INTEGER DEFAULT 0 NOT NULL,
    retail_rate INTEGER DEFAULT 0 NOT NULL,
    eu_wholesale_rate INTEGER DEFAULT 0 NOT NULL,
    ws_retail_rate INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT rc_accounts_account_id_idx UNIQUE (account_id)
);

ALTER SEQUENCE rc_accounts_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('rc_vendors','1');
CREATE TABLE rc_vendors (
    id SERIAL PRIMARY KEY NOT NULL,
    vendor_id VARCHAR(64) NOT NULL,
    vendor_rate INTEGER DEFAULT 0 NOT NULL,
    eu_vendor_rate INTEGER DEFAULT 0 NOT NULL,
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
INSERT INTO version (table_name, table_version) values ('rc_ratesheets','1');
CREATE TABLE rc_ratesheets (
    id SERIAL PRIMARY KEY NOT NULL,
    ratesheet_table VARCHAR(64) NOT NULL,
    eu_rate_format INTEGER NOT NULL,
    currency VARCHAR(64) NOT NULL,
    CONSTRAINT rc_ratesheets_table_idx UNIQUE (ratesheet_table)
);

ALTER SEQUENCE rc_ratesheets_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('rc_demo_ratesheet','1');
CREATE TABLE rc_demo_ratesheet (
    id SERIAL PRIMARY KEY NOT NULL,
    prefix VARCHAR(64) NOT NULL,
    destination VARCHAR(128) NOT NULL,
    destination_id INTEGER DEFAULT 0 NOT NULL,
    price REAL DEFAULT 0 NOT NULL,
    minimum INTEGER DEFAULT 0 NOT NULL,
    increment INTEGER DEFAULT 1 NOT NULL,
    CONSTRAINT rc_demo_ratesheet_prefix_idx UNIQUE (prefix)
);

ALTER SEQUENCE rc_demo_ratesheet_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('rc_demo_eu_ratesheet','1');
CREATE TABLE rc_demo_eu_ratesheet (
    id SERIAL PRIMARY KEY NOT NULL,
    ani_prefix VARCHAR(64) NOT NULL,
    ani_dst_name VARCHAR(128) NOT NULL,
    destination VARCHAR(128) NOT NULL,
    destination_id INTEGER DEFAULT 0 NOT NULL,
    price REAL DEFAULT 0 NOT NULL,
    minimum INTEGER DEFAULT 0 NOT NULL,
    increment INTEGER DEFAULT 1 NOT NULL,
    CONSTRAINT rc_demo_eu_ratesheet_eu_rate_idx UNIQUE (ani_prefix, destination_id)
);

ALTER SEQUENCE rc_demo_eu_ratesheet_id_seq MAXVALUE 2147483647 CYCLE;
