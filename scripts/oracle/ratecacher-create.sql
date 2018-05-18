INSERT INTO version (table_name, table_version) values ('rc_clients','1');
CREATE TABLE rc_clients (
    id NUMBER(10) PRIMARY KEY,
    client_id VARCHAR2(64),
    wholesale_rate NUMBER(10) DEFAULT 0 NOT NULL,
    retail_rate NUMBER(10) DEFAULT 0 NOT NULL,
    CONSTRAINT rc_clients_client_id_idx  UNIQUE (client_id)
);

CREATE OR REPLACE TRIGGER rc_clients_tr
before insert on rc_clients FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END rc_clients_tr;
/
BEGIN map2users('rc_clients'); END;
/
INSERT INTO version (table_name, table_version) values ('rc_vendors','1');
CREATE TABLE rc_vendors (
    id NUMBER(10) PRIMARY KEY,
    vendor_id VARCHAR2(64),
    vendor_rate NUMBER(10) DEFAULT 0 NOT NULL,
    CONSTRAINT rc_vendors_vendor_id_idx  UNIQUE (vendor_id)
);

CREATE OR REPLACE TRIGGER rc_vendors_tr
before insert on rc_vendors FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END rc_vendors_tr;
/
BEGIN map2users('rc_vendors'); END;
/
INSERT INTO version (table_name, table_version) values ('rc_ratesheets','1');
CREATE TABLE rc_ratesheets (
    id NUMBER(10) PRIMARY KEY,
    ratesheet_table VARCHAR2(64),
    currency VARCHAR2(64),
    CONSTRAINT rc_ratesheets_table_idx  UNIQUE (ratesheet_table)
);

CREATE OR REPLACE TRIGGER rc_ratesheets_tr
before insert on rc_ratesheets FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END rc_ratesheets_tr;
/
BEGIN map2users('rc_ratesheets'); END;
/
INSERT INTO version (table_name, table_version) values ('rc_demo_ratesheet','1');
CREATE TABLE rc_demo_ratesheet (
    id NUMBER(10) PRIMARY KEY,
    prefix VARCHAR2(64),
    destination VARCHAR2(128),
    price NUMBER DEFAULT 0 NOT NULL,
    minimum NUMBER(10) DEFAULT 0 NOT NULL,
    increment NUMBER(10) DEFAULT 1 NOT NULL,
    CONSTRAINT rc_demo_ratesheet_prefix_idx  UNIQUE (prefix)
);

CREATE OR REPLACE TRIGGER rc_demo_ratesheet_tr
before insert on rc_demo_ratesheet FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END rc_demo_ratesheet_tr;
/
BEGIN map2users('rc_demo_ratesheet'); END;
/
