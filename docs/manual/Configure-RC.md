---
title: "Configuration RC File"
description: "The opensipsctlrc is the file that contains all the configuration options for the opensipsctl, opensipsdbctl and osipsconsole tools."
---

The **opensipsctlrc** is the file that contains all the configuration options for the opensipsctl, opensipsdbctl and osipsconsole tools.

Upon installation, the file is located in 
```text

[INSTALL_PATH]/etc/opensips/opensipsctlrc

```

The file contains control options for interacting with the database, for run-time interaction with OpenSIPS ( eg. via the [MI interface](Interface-MI.md) ) and also some control options for the provisioning done via the opensipsctl and osipsconsole tools.

The most relevant / used options are the following :

* **SIP_DOMAIN** - The SIP domain for your OpenSIPS proxy, useful for when adding new users in the system ( via the opensipsctl tool )
* **DB** parameters - Contain the DB credentials use by the opensipsdbctl when creating the DB structure, and also by the opensipsctl when inserting provisioning information
* **CTLENGINE** - The transport that will be used by the FIFO engine when running MI commands from the opensipsctl tool. Options are FIFO, XMLRPC and UDP
* **OSIPS_FIFO** - Path to the OpenSIPS FIFO file for the current OpenSIPS instance. In case you have multiple OpenSIPS instances deployed on the same machine, you should change this.
* **STORE_PLAINTEXT_PW** - Controls whether, when adding a user via the "opensipsctl add username" pass command, the password will be stored in plaintext format in the DB, or if the DB should just contained the HASH version of the provided password.
