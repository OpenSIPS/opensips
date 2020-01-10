INSERT INTO version (table_name, table_version) values ('load_balancer','3');
CREATE TABLE load_balancer (
    id NUMBER(10) PRIMARY KEY,
    group_id NUMBER(10) DEFAULT 0 NOT NULL,
    dst_uri VARCHAR2(128),
    resources VARCHAR2(255),
    probe_mode NUMBER(10) DEFAULT 0 NOT NULL,
    attrs VARCHAR2(255) DEFAULT NULL,
    description VARCHAR2(128) DEFAULT NULL
);

CREATE OR REPLACE TRIGGER load_balancer_tr
before insert on load_balancer FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END load_balancer_tr;
/
BEGIN map2users('load_balancer'); END;
/
CREATE INDEX load_balancer_dsturi_idx  ON load_balancer (dst_uri);

