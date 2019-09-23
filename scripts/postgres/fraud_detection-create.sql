INSERT INTO version (table_name, table_version) values ('fraud_detection','1');
CREATE TABLE fraud_detection (
    ruleid SERIAL PRIMARY KEY NOT NULL,
    profileid INTEGER NOT NULL,
    prefix VARCHAR(64) NOT NULL,
    start_hour VARCHAR(5) DEFAULT '00:00' NOT NULL,
    end_hour VARCHAR(5) DEFAULT '23:59' NOT NULL,
    daysoftheweek VARCHAR(64) DEFAULT 'Mon-Sun' NOT NULL,
    cpm_warning INTEGER NOT NULL,
    cpm_critical INTEGER NOT NULL,
    call_duration_warning INTEGER NOT NULL,
    call_duration_critical INTEGER NOT NULL,
    total_calls_warning INTEGER NOT NULL,
    total_calls_critical INTEGER NOT NULL,
    concurrent_calls_warning INTEGER NOT NULL,
    concurrent_calls_critical INTEGER NOT NULL,
    sequential_calls_warning INTEGER NOT NULL,
    sequential_calls_critical INTEGER NOT NULL
);

ALTER SEQUENCE fraud_detection_ruleid_seq MAXVALUE 2147483647 CYCLE;
