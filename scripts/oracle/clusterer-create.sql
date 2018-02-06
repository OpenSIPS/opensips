INSERT INTO version (table_name, table_version) values ('clusterer','4');
CREATE TABLE clusterer (
    id NUMBER(10) PRIMARY KEY,
    cluster_id NUMBER(10),
    node_id NUMBER(10),
    url VARCHAR2(64),
    state NUMBER(10) DEFAULT 1 NOT NULL,
    no_ping_retries NUMBER(10) DEFAULT 3 NOT NULL,
    priority NUMBER(10) DEFAULT 50 NOT NULL,
    sip_addr VARCHAR2(64),
    flags VARCHAR2(64),
    description VARCHAR2(64),
    CONSTRAINT clusterer_clusterer_idx  UNIQUE (cluster_id, node_id)
);

CREATE OR REPLACE TRIGGER clusterer_tr
before insert on clusterer FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END clusterer_tr;
/
BEGIN map2users('clusterer'); END;
/
