INSERT INTO version (table_name, table_version) values ('carrierroute','3');
CREATE TABLE carrierroute (
    id SERIAL PRIMARY KEY NOT NULL,
    carrier INTEGER DEFAULT 0 NOT NULL,
    domain VARCHAR(64) DEFAULT '' NOT NULL,
    scan_prefix VARCHAR(64) DEFAULT '' NOT NULL,
    flags INTEGER DEFAULT 0 NOT NULL,
    mask INTEGER DEFAULT 0 NOT NULL,
    prob REAL DEFAULT 0 NOT NULL,
    strip INTEGER DEFAULT 0 NOT NULL,
    rewrite_host VARCHAR(255) DEFAULT '' NOT NULL,
    rewrite_prefix VARCHAR(64) DEFAULT '' NOT NULL,
    rewrite_suffix VARCHAR(64) DEFAULT '' NOT NULL,
    description VARCHAR(255) DEFAULT NULL
);

ALTER SEQUENCE carrierroute_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('carrierfailureroute','2');
CREATE TABLE carrierfailureroute (
    id SERIAL PRIMARY KEY NOT NULL,
    carrier INTEGER DEFAULT 0 NOT NULL,
    domain VARCHAR(64) DEFAULT '' NOT NULL,
    scan_prefix VARCHAR(64) DEFAULT '' NOT NULL,
    host_name VARCHAR(255) DEFAULT '' NOT NULL,
    reply_code VARCHAR(3) DEFAULT '' NOT NULL,
    flags INTEGER DEFAULT 0 NOT NULL,
    mask INTEGER DEFAULT 0 NOT NULL,
    next_domain VARCHAR(64) DEFAULT '' NOT NULL,
    description VARCHAR(255) DEFAULT NULL
);

ALTER SEQUENCE carrierfailureroute_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('route_tree','2');
CREATE TABLE route_tree (
    id SERIAL PRIMARY KEY NOT NULL,
    carrier VARCHAR(64) DEFAULT NULL
);

ALTER SEQUENCE route_tree_id_seq MAXVALUE 2147483647 CYCLE;
