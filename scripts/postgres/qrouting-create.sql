INSERT INTO version (table_name, table_version) values ('qr_profiles','1');
CREATE TABLE qr_profiles (
    id SERIAL PRIMARY KEY NOT NULL,
    profile_name VARCHAR(64) NOT NULL,
    warn_threshold_asr DOUBLE PRECISION DEFAULT -1 NOT NULL,
    warn_threshold_ccr DOUBLE PRECISION DEFAULT -1 NOT NULL,
    warn_threshold_pdd DOUBLE PRECISION DEFAULT -1 NOT NULL,
    warn_threshold_ast DOUBLE PRECISION DEFAULT -1 NOT NULL,
    warn_threshold_acd DOUBLE PRECISION DEFAULT -1 NOT NULL,
    crit_threshold_asr DOUBLE PRECISION DEFAULT -1 NOT NULL,
    crit_threshold_ccr DOUBLE PRECISION DEFAULT -1 NOT NULL,
    crit_threshold_pdd DOUBLE PRECISION DEFAULT -1 NOT NULL,
    crit_threshold_ast DOUBLE PRECISION DEFAULT -1 NOT NULL,
    crit_threshold_acd DOUBLE PRECISION DEFAULT -1 NOT NULL,
    warn_penalty_asr DOUBLE PRECISION DEFAULT 0.5 NOT NULL,
    warn_penalty_ccr DOUBLE PRECISION DEFAULT 0.5 NOT NULL,
    warn_penalty_pdd DOUBLE PRECISION DEFAULT 0.5 NOT NULL,
    warn_penalty_ast DOUBLE PRECISION DEFAULT 0.5 NOT NULL,
    warn_penalty_acd DOUBLE PRECISION DEFAULT 0.5 NOT NULL,
    crit_penalty_asr DOUBLE PRECISION DEFAULT 0.05 NOT NULL,
    crit_penalty_ccr DOUBLE PRECISION DEFAULT 0.05 NOT NULL,
    crit_penalty_pdd DOUBLE PRECISION DEFAULT 0.05 NOT NULL,
    crit_penalty_ast DOUBLE PRECISION DEFAULT 0.05 NOT NULL,
    crit_penalty_acd DOUBLE PRECISION DEFAULT 0.05 NOT NULL
);

ALTER SEQUENCE qr_profiles_id_seq MAXVALUE 2147483647 CYCLE;
