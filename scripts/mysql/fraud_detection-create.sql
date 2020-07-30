INSERT INTO version (table_name, table_version) values ('fraud_detection','1');
CREATE TABLE fraud_detection (
    ruleid INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    profileid INT UNSIGNED NOT NULL,
    prefix CHAR(64) NOT NULL,
    start_hour CHAR(5) DEFAULT '00:00' NOT NULL,
    end_hour CHAR(5) DEFAULT '23:59' NOT NULL,
    daysoftheweek CHAR(64) DEFAULT 'Mon-Sun' NOT NULL,
    cpm_warning INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    cpm_critical INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    call_duration_warning INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    call_duration_critical INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    total_calls_warning INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    total_calls_critical INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    concurrent_calls_warning INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    concurrent_calls_critical INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    sequential_calls_warning INT(5) UNSIGNED DEFAULT 0 NOT NULL,
    sequential_calls_critical INT(5) UNSIGNED DEFAULT 0 NOT NULL
) ENGINE=InnoDB;

