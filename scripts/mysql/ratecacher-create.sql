INSERT INTO version (table_name, table_version) values ('rc_clients','1');
CREATE TABLE rc_clients (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    client_id CHAR(64) NOT NULL,
    wholesale_rate INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    retail_rate INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    CONSTRAINT client_id_idx UNIQUE (client_id)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('rc_vendors','1');
CREATE TABLE rc_vendors (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    vendor_id CHAR(64) NOT NULL,
    vendor_rate INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    CONSTRAINT vendor_id_idx UNIQUE (vendor_id)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('rc_ratesheets','1');
CREATE TABLE rc_ratesheets (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    ratesheet_table CHAR(64) NOT NULL,
    currency CHAR(64) NOT NULL,
    CONSTRAINT table_idx UNIQUE (ratesheet_table)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('rc_demo_ratesheet','1');
CREATE TABLE rc_demo_ratesheet (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    prefix CHAR(64) NOT NULL,
    destination CHAR(128) NOT NULL,
    price FLOAT DEFAULT 0 NOT NULL,
    minimum INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    increment INT(11) UNSIGNED DEFAULT 1 NOT NULL,
    CONSTRAINT prefix_idx UNIQUE (prefix)
) ENGINE=InnoDB;

