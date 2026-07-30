---
title: "Configuration File"
description: "The OpenSIPS configuration file contains all the parameters that control the OpenSIPS core and modules, along with the actual routing logic that OpenSIPS wil..."
---

The OpenSIPS configuration file contains all the parameters that control the OpenSIPS core and modules, along with the actual routing logic that OpenSIPS will use to route the SIP traffic.

  

Upon installation, the default configuration file path is :

```text

[INSTALL_PATH]/etc/opensips/opensips.cfg

```

  

The configuration file is text-based, written in an OpenSIPS custom language, very similar to the C language. You will find different variables ( each with different scopes - explained further down the manual ), you can do the classical constructs like if / while / switch, etc, and you can also call sub-routines with parameters, so the script should be fairly easily read-able by somebody with some SIP & programming skills.

  

> [!IMPORTANT]
> If you do any change to the configuration file, in order for them to take effect, you MUST restart OpenSIPS

  

Due to the fact that you must restart OpenSIPS every time you make a change to the configuration file, it is of vital importance to ensure that all the changes you have made are correct according to the OpenSIPS language syntax.

You can check the OpenSIPS configuration file validity by running

  

```text

[INSTALL_PATH]/sbin/opensips -C [PATH_TO_CFG]

```

  

When checking the configuration file for validity, If the cfg is OK, OpenSIPS will return 0.

  

If the config file contains any errors, they will be displayed in the console and OpenSIPS will return -1
