INSERT INTO version (table_name, table_version) values ('imc_rooms','2');
CREATE TABLE imc_rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    name CHAR(64) NOT NULL,
    domain CHAR(64) NOT NULL,
    flag INTEGER NOT NULL,
    CONSTRAINT imc_rooms_name_domain_idx  UNIQUE (name, domain)
);

INSERT INTO version (table_name, table_version) values ('imc_members','2');
CREATE TABLE imc_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username CHAR(64) NOT NULL,
    domain CHAR(64) NOT NULL,
    room CHAR(64) NOT NULL,
    flag INTEGER NOT NULL,
    CONSTRAINT imc_members_account_room_idx  UNIQUE (username, domain, room)
);

