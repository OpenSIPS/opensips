---
title: "Conformance Tests"
description: "Conformance/Conformity tests are being run in order to validate OpenSIPS behavior in certain scenarios. The goal is to provide insurance that any change to O..."
---

Conformance/Conformity tests are being run in order to validate OpenSIPS behavior in certain scenarios. The goal is to provide insurance that any change to OpenSIPS' code (either due to bug fixes or new features) are running according to the desired specifications and that there are no regressions.

To this end, we have developed a set of tests set that execute OpenSIPS in different scenarios with different SIP flows, and validate that all the involved components (OpenSIPS as well as databases, provisioning, SIP UAs) are inter-operating correctly and their behavior is the expected one.

---

## Setup

The first requirement is to install [SIPssert](https://github.com/OpenSIPS/SIPssert) - a testing framework capable of orchestrating complex conformance scenarios and verify their execution. You can follow the [install instructions](https://github.com/OpenSIPS/SIPssert#installation) on the project's page.

Next, we need to fetch the tests available. For the initial setup, we need to clone the repository:
```text

git clone git@github.com:OpenSIPS/sipssert-opensips-tests.git

```

If you are targeting a stable release, make sure you specify the OpenSIPS branch/version you need:
```text

git clone -b 4.1 git@github.com:OpenSIPS/sipssert-opensips-tests.git

```

Navigate to the tests' directory. If the repository has been previously cloned, make sure you keep it up to date by running:
```text

git pull --rebase

```

---

## Testing

Once SIPssert is in place and the tests repository is cloned, you need to navigate to the tests repository and run:
```text

sipssert *

```

This command will run all the available tests sets, with the default configuration. If you want to test only a specific tests set, or only a specific test, you may provide additional arguments to the `sipssert` tool. See [Instructions](https://github.com/OpenSIPS/SIPssert#usage) page for more information. 

---

## Development

There is always place for developing new tests, either to ensure old code behaves properly, either to prove that it does not - any contribution is welcome. Therefore, if you have a new test you want to include, feel free to open a pull request on the [project's tracker](https://github.com/OpenSIPS/sipssert-opensips-tests/pulls).
