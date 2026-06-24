---
title: "Generating Config Files"
description: "Use the OpenSIPS GNU M4 templates to create residential, trunking, and load-balancer configurations."
---

OpenSIPS provides ready-to-use GNU M4 configuration templates under
`examples/templates/`:

* `residential.m4`
* `trunking.m4`
* `loadbalancer.m4`

They are installed as shared examples under
`$PREFIX/share/opensips/examples/templates/`. Distribution packages typically
use `/usr/share/opensips/examples/templates/`.

Each template starts with definitions for its listening interface, database
URL, optional endpoints, and feature switches. Edit these definitions before
using the template. Feature switches accept `yes` or `no`.

## Run a template directly

Use `-f` to select the template and `-p m4` to preprocess it before OpenSIPS
parses it:

```bash
opensips -C -f examples/templates/residential.m4 -p m4
opensips -f examples/templates/residential.m4 -p m4
```

The first command checks the generated configuration. The second starts
OpenSIPS. GNU M4 must be installed and available in `PATH`.

For an installed distribution package, use the template from the shared
examples directory:

```bash
opensips -f /usr/share/opensips/examples/templates/residential.m4 -p m4
```

## Create a standalone configuration

You can render a template into a regular configuration file:

```bash
m4 examples/templates/residential.m4 > opensips.cfg
```

The resulting file no longer requires preprocessing. Edit it as needed, then
check or start it normally:

```bash
opensips -C -f opensips.cfg
opensips -f opensips.cfg
```

See `examples/templates/README.md` for additional examples.
