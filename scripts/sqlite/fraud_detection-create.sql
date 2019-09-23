INSERT INTO version (table_name, table_version) values ('fraud_detection','1');
CREATE TABLE fraud_detection (
    ruleid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    profileid INTEGER NOT NULL,
    prefix CHAR(64) NOT NULL,
    start_hour CHAR(5) DEFAULT '00:00' NOT NULL,
    end_hour CHAR(5) DEFAULT '23:59' NOT NULL,
    daysoftheweek CHAR(64) DEFAULT 'Mon-Sun' NOT NULL,
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

