INSERT INTO version (table_name, table_version) values ('fraud_detection','1');
CREATE TABLE fraud_detection (
    ruleid NUMBER(10) PRIMARY KEY,
    profileid NUMBER(10),
    prefix VARCHAR2(64),
    start_hour VARCHAR2(5) DEFAULT '00:00',
    end_hour VARCHAR2(5) DEFAULT '23:59',
    daysoftheweek VARCHAR2(64) DEFAULT 'Mon-Sun',
    cpm_warning NUMBER(10) DEFAULT 0 NOT NULL,
    cpm_critical NUMBER(10) DEFAULT 0 NOT NULL,
    call_duration_warning NUMBER(10) DEFAULT 0 NOT NULL,
    call_duration_critical NUMBER(10) DEFAULT 0 NOT NULL,
    total_calls_warning NUMBER(10) DEFAULT 0 NOT NULL,
    total_calls_critical NUMBER(10) DEFAULT 0 NOT NULL,
    concurrent_calls_warning NUMBER(10) DEFAULT 0 NOT NULL,
    concurrent_calls_critical NUMBER(10) DEFAULT 0 NOT NULL,
    sequential_calls_warning NUMBER(10) DEFAULT 0 NOT NULL,
    sequential_calls_critical NUMBER(10) DEFAULT 0 NOT NULL
);

CREATE OR REPLACE TRIGGER fraud_detection_tr
before insert on fraud_detection FOR EACH ROW
BEGIN
  auto_id(:NEW.id);
END fraud_detection_tr;
/
BEGIN map2users('fraud_detection'); END;
/
