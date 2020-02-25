INSERT INTO version (table_name, table_version) values ('qr_profiles','1');
CREATE TABLE qr_profiles (
    id NUMBER(10) PRIMARY KEY,
    profile_name VARCHAR2(64),
    warn_threshold_asr NUMBER DEFAULT -1 NOT NULL,
    warn_threshold_ccr NUMBER DEFAULT -1 NOT NULL,
    warn_threshold_pdd NUMBER DEFAULT -1 NOT NULL,
    warn_threshold_ast NUMBER DEFAULT -1 NOT NULL,
    warn_threshold_acd NUMBER DEFAULT -1 NOT NULL,
    crit_threshold_asr NUMBER DEFAULT -1 NOT NULL,
    crit_threshold_ccr NUMBER DEFAULT -1 NOT NULL,
    crit_threshold_pdd NUMBER DEFAULT -1 NOT NULL,
    crit_threshold_ast NUMBER DEFAULT -1 NOT NULL,
    crit_threshold_acd NUMBER DEFAULT -1 NOT NULL,
    warn_penalty_asr NUMBER DEFAULT 0.5 NOT NULL,
    warn_penalty_ccr NUMBER DEFAULT 0.5 NOT NULL,
    warn_penalty_pdd NUMBER DEFAULT 0.5 NOT NULL,
    warn_penalty_ast NUMBER DEFAULT 0.5 NOT NULL,
    warn_penalty_acd NUMBER DEFAULT 0.5 NOT NULL,
    crit_penalty_asr NUMBER DEFAULT 0.05 NOT NULL,
    crit_penalty_ccr NUMBER DEFAULT 0.05 NOT NULL,
    crit_penalty_pdd NUMBER DEFAULT 0.05 NOT NULL,
    crit_penalty_ast NUMBER DEFAULT 0.05 NOT NULL,
    crit_penalty_acd NUMBER DEFAULT 0.05 NOT NULL
);

CREATE OR REPLACE TRIGGER qr_profiles_tr
before insert on qr_profiles FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END qr_profiles_tr;
/
BEGIN map2users('qr_profiles'); END;
/
