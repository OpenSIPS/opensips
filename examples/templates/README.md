# OpenSIPS configuration templates

This directory contains ready-to-use GNU M4 templates for common OpenSIPS
deployments:

- `loadbalancer.m4`
- `residential.m4`
- `trunking.m4`

Source builds install these examples under
`$PREFIX/share/opensips/examples/templates/`. The default prefix places them
under `/usr/local/share/opensips/examples/templates/`; distribution packages
typically use `/usr/share/opensips/examples/templates/`.

Each template begins with its available definitions. Set `LISTEN_IP` to the IP
address or interface OpenSIPS should listen on, set `DB_URL` to the database
connection URL, and set each feature switch to `yes` or `no`. Then customize
the remaining endpoint definitions as required by the deployment.

To check the load-balancer template from the repository root, run:

```console
opensips -C -f examples/templates/loadbalancer.m4 -p m4
```

Remove `-C` to start OpenSIPS:

```console
opensips -f examples/templates/loadbalancer.m4 -p m4
```

The `-f` option selects the configuration template. The `-p m4` option pipes
that template through GNU M4 before OpenSIPS parses it. GNU M4 must be installed
and available in `PATH`.

When using an installed distribution package, run the template from the shared
examples directory instead:

```console
opensips -f /usr/share/opensips/examples/templates/loadbalancer.m4 -p m4
```

Use the same commands with `residential.m4` or `trunking.m4` for the other
scenarios.

## Create a standalone configuration file

You can render any template into a regular OpenSIPS configuration file. For
example:

```console
m4 examples/templates/loadbalancer.m4 > opensips.cfg
```

The resulting `opensips.cfg` no longer requires M4 preprocessing. You can edit
it freely and then check or start it as a normal configuration file:

```console
opensips -C -f opensips.cfg
opensips -f opensips.cfg
```
