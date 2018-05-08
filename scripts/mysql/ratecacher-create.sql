INSERT INTO version (table_name, table_version) values ('rc_accounts','1');
CREATE TABLE rc_accounts (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    account_id CHAR(64) NOT NULL,
    wholesale_rate INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    retail_rate INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    eu_wholesale_rate INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    ws_retail_rate INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    CONSTRAINT account_id_idx UNIQUE (account_id)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('rc_vendors','1');
CREATE TABLE rc_vendors (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    vendor_id CHAR(64) NOT NULL,
    vendor_rate INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    eu_vendor_rate INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    CONSTRAINT vendor_id_idx UNIQUE (vendor_id)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('rc_ratesheets','1');
CREATE TABLE rc_ratesheets (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    ratesheet_table CHAR(64) NOT NULL,
    currency CHAR(64) NOT NULL,
    CONSTRAINT table_idx UNIQUE (ratesheet_table)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('rc_ratesheets','1');
CREATE TABLE rc_ratesheets (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    ratesheet_table CHAR(64) NOT NULL,
    eu_rate_format INT(11) UNSIGNED NOT NULL,
    currency CHAR(64) NOT NULL,
    CONSTRAINT table_idx UNIQUE (ratesheet_table)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('rc_demo_ratesheet','1');
CREATE TABLE rc_demo_ratesheet (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    prefix CHAR(64) NOT NULL,
    destination CHAR(128) NOT NULL,
    destination_id INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    price FLOAT DEFAULT 0 NOT NULL,
    minimum INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    increment INT(11) UNSIGNED DEFAULT 1 NOT NULL,
    CONSTRAINT prefix_idx UNIQUE (prefix)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('rc_demo_eu_ratesheet','1');
CREATE TABLE rc_demo_eu_ratesheet (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    ani_prefix CHAR(64) NOT NULL,
    ani_dst_name CHAR(128) NOT NULL,
    destination CHAR(128) NOT NULL,
    destination_id INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    price FLOAT DEFAULT 0 NOT NULL,
    minimum INT(11) UNSIGNED DEFAULT 0 NOT NULL,
    increment INT(11) UNSIGNED DEFAULT 1 NOT NULL,
    CONSTRAINT eu_rate_idx UNIQUE (ani_prefix, destination_id)
) ENGINE=InnoDB;

