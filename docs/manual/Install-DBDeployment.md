---
title: "Database Deployment"
description: "After installing your OpenSIPS, most likely you will need to also deploy a database that you could use for various reasons ( DB user authentication, persiste..."
---

After installing your OpenSIPS, most likely you will need to also deploy a database that you could use for various reasons ( DB user authentication, persistent registrations, dialogs, etc ).

---

## Configuring DB Credentials

Go to the [Install_Path]/etc/opensips/ folder and open the opensipsctlrc file

There take care of the following lines :

* DBENGINE=
  * the currently available options MYSQL, PGSQL, ORACLE, DB_BERKELEY, or DBTEXT
* DBHOST=
  * enter the host for your DB engine
* DBNAME=
  * the name of the database which will be created
* DBRWUSER=
  * the username that will be created in the database for OpenSIPS read/write access
* DBRWPW=
  * the password that will be set for the DBRWUSER username
* DBROOTUSER=
  * the user that will be used for creating the database, tables and DBRWUSER

## Creating the Database

In order to create the DBNAME database that you have provisioned above, run
```text

[Install_Path]/sbin/opensipsdbctl create

```

When prompted by the opensipsdbctl tool, please enter your DBROOTUSER password.

If you want to create a different database other than the default DBNAME, you can call
```text

[Install_Path]/sbin/opensipsdbctl create my_custom_db_name

```

The opensipsdbctl tool can also be used for things like taking backups, doing restores, and more. If you want to see the capabilities and help manual for the opensipsdbctl tool, you can run it with no parameters :
```text

[Install_Path]/sbin/opensipsdbctl

```
