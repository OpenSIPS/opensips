INSERT INTO version (table_name, table_version) values ('cachedb','2');
CREATE TABLE cachedb (
    keyname VARCHAR2(255) PRIMARY KEY,
    value CLOB,
    counter NUMBER(10) DEFAULT 0 NOT NULL,
    expires NUMBER(10) DEFAULT 0 NOT NULL
);

BEGIN map2users('cachedb'); END;
/
