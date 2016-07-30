INSERT INTO version (table_name, table_version) values ('fraud_detection','1');
CREATE TABLE fraud_detection (
    ruleid INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    profileid INT UNSIGNED NOT NULL,
    prefix CHAR(64) NOT NULL,
    start_hour CHAR(5) NOT NULL,
    end_hour CHAR(5) NOT NULL,
    daysoftheweek CHAR(64) NOT NULL,
    cpm_warning INT(5) UNSIGNED NOT NULL,
    cpm_critical INT(5) UNSIGNED NOT NULL,
    call_duration_warning INT(5) UNSIGNED NOT NULL,
    call_duration_critical INT(5) UNSIGNED NOT NULL,
    total_calls_warning INT(5) UNSIGNED NOT NULL,
    total_calls_critical INT(5) UNSIGNED NOT NULL,
    concurrent_calls_warning INT(5) UNSIGNED NOT NULL,
    concurrent_calls_critical INT(5) UNSIGNED NOT NULL,
    sequential_calls_warning INT(5) UNSIGNED NOT NULL,
    sequential_calls_critical INT(5) UNSIGNED NOT NULL
) ENGINE=InnoDB;

