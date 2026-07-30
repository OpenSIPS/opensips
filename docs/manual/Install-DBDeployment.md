---
title: "Database Deployment"
description: "After installing your OpenSIPS, most likely you will need to also deploy a database that you could use for various reasons ( DB user authentication, persiste..."
---

After installing your OpenSIPS, most likely you will need to also deploy a database that you could use for various reasons ( DB user authentication, persistent registrations, dialogs, etc ).

---

You can deploy the opensips database using the [opensips-cli](https://github.com/OpenSIPS/opensips-cli) tool. Before you do that, you should [install it](https://github.com/OpenSIPS/opensips-cli#install).

## Configuring OpenSIPS CLI

Open your OpenSIPS CLI configuration file and specify the following parameters:
* `database_schema_path` - (defaults to `/usr/share/opensips/`) set it to `[Install_Path]/share/opensips/`
* `database_url` - the URL to connect to your database (if not specified, you will be prompted for it during deploy)
* `database_name` - (defaults to `opensips`) the database to use
* `database_modules` - (defaults to standard modules) the modules you want to deploy.

You can find more information about the OpenSIPS CLI tool configuration [here](https://github.com/OpenSIPS/opensips-cli/blob/master/docs/modules/database.md#configuration).

> [!NOTE]
> OpenSIPS CLI searches for its configuration files in `~/.opensips-cli.cfg`, `/etc/opensips-cli.cfg`, `/etc/opensips/opensips-cli.cfg`, but you can also specify your own configuration file using the `-f` parameter.

## Creating the Database

In order to create the `database_name` database that you have provisioned above, run
```bash

opensips-cli -x database create

```

Later, if you decide to add a new module, for example presence, simply call:
```bash

opensips-cli -x database add presence

```

You can also specify a different name for the database, for example `opensips_test`, using:
```bash

opensips-cli -x database create opensips_test

```
