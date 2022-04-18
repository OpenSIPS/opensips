INSERT INTO version (table_name, table_version) values ('tcp_mgm','1');
CREATE TABLE tcp_mgm (
    id SERIAL PRIMARY KEY NOT NULL,
    proto VARCHAR(8) DEFAULT 'any' NOT NULL,
    remote_addr VARCHAR(43) DEFAULT NULL,
    remote_port INTEGER DEFAULT 0 NOT NULL,
    local_addr VARCHAR(43) DEFAULT NULL,
    local_port INTEGER DEFAULT 0 NOT NULL,
    priority INTEGER DEFAULT 0 NOT NULL,
    connect_timeout INTEGER DEFAULT 100 NOT NULL,
    con_lifetime INTEGER DEFAULT 120 NOT NULL,
    msg_read_timeout INTEGER DEFAULT 4 NOT NULL,
    send_threshold INTEGER DEFAULT 0 NOT NULL,
    no_new_conn INTEGER DEFAULT 0 NOT NULL,
    alias_mode INTEGER DEFAULT 0 NOT NULL,
    keepalive INTEGER DEFAULT 1 NOT NULL,
    keepcount INTEGER DEFAULT 9 NOT NULL,
    keepidle INTEGER DEFAULT 7200 NOT NULL,
    keepinterval INTEGER DEFAULT 75 NOT NULL
);

ALTER SEQUENCE tcp_mgm_id_seq MAXVALUE 2147483647 CYCLE;
