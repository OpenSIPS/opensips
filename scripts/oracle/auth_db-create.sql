INSERT INTO version (table_name, table_version) values ('subscriber','7');
CREATE TABLE subscriber (
    id NUMBER(10) PRIMARY KEY,
    username VARCHAR2(64) DEFAULT '',
    domain VARCHAR2(64) DEFAULT '',
    password VARCHAR2(25) DEFAULT '',
    email_address VARCHAR2(64) DEFAULT '',
    ha1 VARCHAR2(64) DEFAULT '',
    ha1b VARCHAR2(64) DEFAULT '',
    rpid VARCHAR2(64) DEFAULT NULL,
    CONSTRAINT subscriber_account_idx  UNIQUE (username, domain)
);

CREATE OR REPLACE TRIGGER subscriber_tr
before insert on subscriber FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END subscriber_tr;
/
BEGIN map2users('subscriber'); END;
/
CREATE INDEX subscriber_username_idx  ON subscriber (username);

INSERT INTO version (table_name, table_version) values ('uri','2');
CREATE TABLE uri (
    id NUMBER(10) PRIMARY KEY,
    username VARCHAR2(64) DEFAULT '',
    domain VARCHAR2(64) DEFAULT '',
    uri_user VARCHAR2(64) DEFAULT '',
    last_modified DATE DEFAULT to_date('1900-01-01 00:00:01','yyyy-mm-dd hh24:mi:ss'),
    CONSTRAINT uri_account_idx  UNIQUE (username, domain, uri_user)
);

CREATE OR REPLACE TRIGGER uri_tr
before insert on uri FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END uri_tr;
/
BEGIN map2users('uri'); END;
/
