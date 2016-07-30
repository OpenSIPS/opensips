INSERT INTO version (table_name, table_version) values ('clusterer','1');
CREATE TABLE clusterer (
    id NUMBER(10) PRIMARY KEY,
    cluster_id NUMBER(10),
    machine_id NUMBER(10),
    url VARCHAR2(64),
    state NUMBER(10) DEFAULT 1 NOT NULL,
    last_attempt BIGINT(64) DEFAULT 0 NOT NULL,
    failed_attempts NUMBER(10) DEFAULT 3 NOT NULL,
    no_tries NUMBER(10) DEFAULT 0 NOT NULL,
    duration NUMBER(10) DEFAULT 30 NOT NULL,
    description VARCHAR2(64),
    CONSTRAINT clusterer_clusterer_idx  UNIQUE (cluster_id, machine_id)
);

CREATE OR REPLACE TRIGGER clusterer_tr
before insert on clusterer FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END clusterer_tr;
/
BEGIN map2users('clusterer'); END;
/
