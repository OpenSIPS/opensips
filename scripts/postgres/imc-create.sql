INSERT INTO version (table_name, table_version) values ('imc_rooms','2');
CREATE TABLE imc_rooms (
    id SERIAL PRIMARY KEY NOT NULL,
    name VARCHAR(64) NOT NULL,
    domain VARCHAR(64) NOT NULL,
    flag INTEGER NOT NULL,
    CONSTRAINT imc_rooms_name_domain_idx UNIQUE (name, domain)
);

ALTER SEQUENCE imc_rooms_id_seq MAXVALUE 2147483647 CYCLE;
INSERT INTO version (table_name, table_version) values ('imc_members','2');
CREATE TABLE imc_members (
    id SERIAL PRIMARY KEY NOT NULL,
    username VARCHAR(64) NOT NULL,
    domain VARCHAR(64) NOT NULL,
    room VARCHAR(64) NOT NULL,
    flag INTEGER NOT NULL,
    CONSTRAINT imc_members_account_room_idx UNIQUE (username, domain, room)
);

ALTER SEQUENCE imc_members_id_seq MAXVALUE 2147483647 CYCLE;
