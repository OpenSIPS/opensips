INSERT INTO version (table_name, table_version) values ('cachedb','1');
CREATE TABLE cachedb (
    keyname VARCHAR2(255),
    value CLOB(512),
    counter NUMBER(10) DEFAULT 0 NOT NULL,
    expires NUMBER(10) DEFAULT 0 NOT NULL
);

CREATE OR REPLACE TRIGGER cachedb_tr
before insert on cachedb FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END cachedb_tr;
/
BEGIN map2users('cachedb'); END;
/
