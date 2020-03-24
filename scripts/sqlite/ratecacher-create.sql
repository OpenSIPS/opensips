INSERT INTO version (table_name, table_version) values ('rc_clients','1');
CREATE TABLE rc_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    client_id CHAR(64) NOT NULL,
    wholesale_rate INTEGER DEFAULT 0 NOT NULL,
    retail_rate INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT rc_clients_client_id_idx  UNIQUE (client_id)
);

INSERT INTO version (table_name, table_version) values ('rc_vendors','1');
CREATE TABLE rc_vendors (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    vendor_id CHAR(64) NOT NULL,
    vendor_rate INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT rc_vendors_vendor_id_idx  UNIQUE (vendor_id)
);

INSERT INTO version (table_name, table_version) values ('rc_ratesheets','1');
CREATE TABLE rc_ratesheets (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    ratesheet_table CHAR(64) NOT NULL,
    currency CHAR(64) NOT NULL,
    CONSTRAINT rc_ratesheets_table_idx  UNIQUE (ratesheet_table)
);

INSERT INTO version (table_name, table_version) values ('rc_demo_ratesheet','1');
CREATE TABLE rc_demo_ratesheet (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    prefix CHAR(64) NOT NULL,
    destination CHAR(128) NOT NULL,
    price FLOAT DEFAULT 0 NOT NULL,
    minimum INTEGER DEFAULT 0 NOT NULL,
    increment INTEGER DEFAULT 1 NOT NULL,
    CONSTRAINT rc_demo_ratesheet_prefix_idx  UNIQUE (prefix)
);

