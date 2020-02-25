INSERT INTO version (table_name, table_version) values ('qr_profiles','1');
CREATE TABLE qr_profiles (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    profile_name CHAR(64) NOT NULL,
    warn_threshold_asr DOUBLE DEFAULT -1 NOT NULL,
    warn_threshold_ccr DOUBLE DEFAULT -1 NOT NULL,
    warn_threshold_pdd DOUBLE DEFAULT -1 NOT NULL,
    warn_threshold_ast DOUBLE DEFAULT -1 NOT NULL,
    warn_threshold_acd DOUBLE DEFAULT -1 NOT NULL,
    crit_threshold_asr DOUBLE DEFAULT -1 NOT NULL,
    crit_threshold_ccr DOUBLE DEFAULT -1 NOT NULL,
    crit_threshold_pdd DOUBLE DEFAULT -1 NOT NULL,
    crit_threshold_ast DOUBLE DEFAULT -1 NOT NULL,
    crit_threshold_acd DOUBLE DEFAULT -1 NOT NULL,
    warn_penalty_asr DOUBLE DEFAULT 0.5 NOT NULL,
    warn_penalty_ccr DOUBLE DEFAULT 0.5 NOT NULL,
    warn_penalty_pdd DOUBLE DEFAULT 0.5 NOT NULL,
    warn_penalty_ast DOUBLE DEFAULT 0.5 NOT NULL,
    warn_penalty_acd DOUBLE DEFAULT 0.5 NOT NULL,
    crit_penalty_asr DOUBLE DEFAULT 0.05 NOT NULL,
    crit_penalty_ccr DOUBLE DEFAULT 0.05 NOT NULL,
    crit_penalty_pdd DOUBLE DEFAULT 0.05 NOT NULL,
    crit_penalty_ast DOUBLE DEFAULT 0.05 NOT NULL,
    crit_penalty_acd DOUBLE DEFAULT 0.05 NOT NULL
) ENGINE=InnoDB;

