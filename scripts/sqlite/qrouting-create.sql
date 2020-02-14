INSERT INTO version (table_name, table_version) values ('qr_profiles','1');
CREATE TABLE qr_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    profile_name CHAR(64) NOT NULL,
    weight_asr DOUBLE DEFAULT 1 NOT NULL,
    weight_ccr DOUBLE DEFAULT 1 NOT NULL,
    weight_pdd DOUBLE DEFAULT 1 NOT NULL,
    weight_ast DOUBLE DEFAULT 1 NOT NULL,
    weight_acd DOUBLE DEFAULT 1 NOT NULL,
    warn_threshold_asr DOUBLE DEFAULT -1 NOT NULL,
    warn_threshold_ccr DOUBLE DEFAULT -1 NOT NULL,
    warn_threshold_pdd DOUBLE DEFAULT -1 NOT NULL,
    warn_threshold_ast DOUBLE DEFAULT -1 NOT NULL,
    warn_threshold_acd DOUBLE DEFAULT -1 NOT NULL,
    crit_threshold_asr DOUBLE DEFAULT -1 NOT NULL,
    crit_threshold_ccr DOUBLE DEFAULT -1 NOT NULL,
    crit_threshold_pdd DOUBLE DEFAULT -1 NOT NULL,
    crit_threshold_ast DOUBLE DEFAULT -1 NOT NULL,
    crit_threshold_acd DOUBLE DEFAULT -1 NOT NULL
);

