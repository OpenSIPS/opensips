INSERT INTO version (table_name, table_version) values ('jwt_profiles','1');
CREATE TABLE jwt_profiles (
    id NUMBER(10) PRIMARY KEY,
    tag VARCHAR2(128),
    sip_username VARCHAR2(128),
    CONSTRAINT jwt_profiles_jwt_tag_idx  UNIQUE (tag)
);

CREATE OR REPLACE TRIGGER jwt_profiles_tr
before insert on jwt_profiles FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END jwt_profiles_tr;
/
BEGIN map2users('jwt_profiles'); END;
/
INSERT INTO version (table_name, table_version) values ('jwt_secrets','1');
CREATE TABLE jwt_secrets (
    id NUMBER(10) PRIMARY KEY,
    corresponding_tag VARCHAR2(128),
    secret CLOB,
    start_ts NUMBER(10),
    end_ts NUMBER(10)
);

CREATE OR REPLACE TRIGGER jwt_secrets_tr
before insert on jwt_secrets FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END jwt_secrets_tr;
/
BEGIN map2users('jwt_secrets'); END;
/
