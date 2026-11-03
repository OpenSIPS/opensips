# OpenSIPS community-contributed modules

This directory contains modules contributed by the OpenSIPS community which
are not maintained by the OpenSIPS core team.  Their inclusion here does not
carry the same maintenance or support expectations as modules under
`modules/`.

These modules are intentionally excluded from the default `make`, `make all`,
`make modules`, and `make install` targets.  Build and install them explicitly:

    make modules-contrib
    make all-modules

Install selected contrib modules using the generic install target:

    make modules=modules-contrib/example install-modules-all

To build a subset, use the same `modules` selector as for core modules:

    make modules=modules-contrib/example modules-contrib

Each module must use the usual `modules/<name>/` layout.  Since both module
trees have the same directory depth, a contrib module Makefile includes the
standard build files in the same way:

    include ../../Makefile.defs
    # module-specific settings
    include ../../Makefile.modules

The Debian and RPM packaging builds place dependency-free modules from this
directory in `opensips-modules-contrib`. A module with external dependencies
must be added to the explicit contrib dependency list in both packaging
backends and shipped as `opensips-module-contrib-<module>`.
