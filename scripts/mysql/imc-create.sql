INSERT INTO version (table_name, table_version) values ('imc_rooms','2');
CREATE TABLE imc_rooms (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    name CHAR(64) NOT NULL,
    domain CHAR(64) NOT NULL,
    flag INT(11) NOT NULL,
    CONSTRAINT name_domain_idx UNIQUE (name, domain)
) ENGINE=InnoDB;

INSERT INTO version (table_name, table_version) values ('imc_members','2');
CREATE TABLE imc_members (
    id INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL,
    username CHAR(64) NOT NULL,
    domain CHAR(64) NOT NULL,
    room CHAR(64) NOT NULL,
    flag INT(11) NOT NULL,
    CONSTRAINT account_room_idx UNIQUE (username, domain, room)
) ENGINE=InnoDB;

