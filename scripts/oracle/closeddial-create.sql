INSERT INTO version (table_name, table_version) values ('closeddial','1');
CREATE TABLE closeddial (
    id NUMBER(10) PRIMARY KEY,
    username VARCHAR2(64) DEFAULT '',
    domain VARCHAR2(64) DEFAULT '',
    cd_username VARCHAR2(64) DEFAULT '',
    cd_domain VARCHAR2(64) DEFAULT '',
    group_id VARCHAR2(64) DEFAULT '',
    new_uri VARCHAR2(255) DEFAULT '',
    CONSTRAINT closeddial_cd_idx1  UNIQUE (username, domain, cd_domain, cd_username, group_id)
);

CREATE OR REPLACE TRIGGER closeddial_tr
before insert on closeddial FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END closeddial_tr;
/
BEGIN map2users('closeddial'); END;
/
CREATE INDEX closeddial_cd_idx2  ON closeddial (group_id);
CREATE INDEX closeddial_cd_idx3  ON closeddial (cd_username);
CREATE INDEX closeddial_cd_idx4  ON closeddial (username);

