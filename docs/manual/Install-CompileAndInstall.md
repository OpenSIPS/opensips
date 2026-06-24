---
title: "Compile And Install"
description: "Compile and install OpenSIPS from source using Makefile.conf."
---

This page is for users compiling OpenSIPS from source. Binary packages should
be installed with the package manager provided by the operating system.

## Configure the build

Build settings are stored in `Makefile.conf` at the repository root. The first
`make` invocation creates it from `Makefile.conf.template` if it does not
already exist. To prepare it explicitly:

```bash
cp Makefile.conf.template Makefile.conf
```

Edit `Makefile.conf` before compiling. Keep this file for subsequent rebuilds;
it is intentionally not tracked by Git.

### Select modules

`exclude_modules` lists modules omitted from the normal `modules` and `all`
targets. The default list primarily contains modules with external
dependencies. Remove a module from this list after installing its development
dependencies, or add it to `include_modules` to force it into the build without
rewriting the default exclusion list:

```make
include_modules += db_mysql json
```

You may explicitly exclude additional modules:

```make
exclude_modules += cachedb_redis event_rabbitmq
```

`include_modules` takes precedence for the named modules. Module names are the
directory names under `modules/`.

For a one-off build, the same variables may be supplied on the command line:

```bash
make -j4 modules include_modules="db_mysql json"
make -j4 modules skip_modules="cachedb_redis event_rabbitmq"
```

### Tune compiler and linker flags

Use `CC_EXTRA_OPTS` and `LD_EXTRA_OPTS` for additional compiler and linker
options:

```make
CC_EXTRA_OPTS += -O2 -march=native
LD_EXTRA_OPTS += -Wl,--as-needed
```

Use `DEFS` for OpenSIPS compile-time definitions. `Makefile.conf.template`
contains the supported definitions with short descriptions. Enable a disabled
definition by uncommenting it, or add a definition explicitly:

```make
DEFS += -DEXTRA_DEBUG
DEFS += -DSHM_EXTRA_STATS
```

Only enable flags whose behavior is understood. Some allocator and locking
definitions are mutually exclusive or materially affect runtime performance.
Run `make proper` before rebuilding after changing compiler flags or
compile-time definitions.

### Configure the installation prefix

Set `PREFIX` in `Makefile.conf` to change the default installation root:

```make
PREFIX ?= /opt/opensips/
```

Use the same prefix for compilation and installation because the default
configuration path is compiled into the OpenSIPS binary.

## Compile

Build the core and selected modules:

```bash
make -j4 all
```

Useful narrower targets are:

```bash
make -j1                 # core binary only
make -j4 modules         # selected modules only
make -j1 modules module=db_mysql
```

## Install

Install the core, selected modules, documentation, and database schemas using
the settings from `Makefile.conf`:

```bash
make install
```

Command-line variables override the corresponding configuration for a one-off
operation. Pass the same values to both build and install steps.
