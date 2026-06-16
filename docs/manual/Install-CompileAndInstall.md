---
title: "Compile And Install"
description: "The following page of the manual is addressed to users that want to compile and install OpenSIPS 2.4 from sources."
---

The following page of the manual is addressed to users that want to compile and install OpenSIPS 2.4 from sources.

> [!TIP]
> If you have download an OpenSIPS package, than please feel free to skip this page, and install your package according to your platform ( dpkg for Debian, rpm for CentOS, etc ).

Go for the **OpenSIPS** [install instructions](https://github.com/OpenSIPS/opensips/blob/2.4/INSTALL) - this is a link directly to the INSTALL file from the SVN repository, which contains the up-to-date version.

The INSTALL file provides information about:

* Supported Architectures and Requirements
* Howto Build OpenSIPS From Source Distribution
* Quick-Start Installation Guide
  * Getting Help
  * Disclaimers
  * Quick Start
  * OpenSIPS with Persistent Data Storage
* Troubleshooting

---

## Video Tutorial

The OpenSIPS team has held a webinar, which will guide you through the process of doing a quick installation of OpenSIPS ( downloading sources, compiling, installing, etc ) and OpenSIPS Control Panel ( installing, provisioning users ), and will show you what you have to do in order to get a fully functional platform in a matter of minutes. If you find video tutorials easier that text based ones, please feel free to go to the [OpenSIPS Installation Webinar](https://docs.opensips.org/tutorials-gettingstarted) page and download the webinar recording.

## Compile

Navigate to the OpenSIPS sources root folder. From this folder you can simply run
```bash

make all

```

and the OpenSIPS core, along with all it's configured modules, will be compiled.

### Configuring Compilation Flags

OpenSIPS has various compile-time options, that affect it's capabilities. For example, you can opt to enable the memory debugging allocator, or to enable TLS ( which is by default disabled ), etc.

In order to change such compile-time options, you should use the 'menuconfig' tool. Since the menuconfig tool is curses-based, before attempting to run it you should install the ncurses development library. On Debian based system, you can usually do this by running
```bash

apt-get install libncurses5-dev

```

After that you can go to the OpenSIPS sources root folder, and run
```bash

make menuconfig

```

Navigate to the 'Configure Compile Options' menu, Here you can simply use the arrows keys ( UP + DOWN ) to go through all the Options ( they are explained briefly at the bottom of the console ). Enabling or disabling an option is done via the SpaceBar key. After finishing your configurations, you can go back via the 'q' key and then hit 'Save Changes'.

After any changes to the Compilation Flags, you should re-compile & re-install your OpenSIPS.

### Compiling Modules with External Dependencies

There are some OpenSIPS modules which are not compiled by default, since they require external dependencies which may or not come by default on your system. Thus, such modules require your manual attention when downloading & installing from sources. Some examples of such modules are DB_MYSQL ( depends on the mysql devel library ), JSON ( depends on the external JSON parser ), etc.

To enable the compilation of such modules, you should use the menuconfig tool as well.

Run 'make menuconfig' from the OpenSIPS sources root folder, and then go to 'Configure Excluded Modules'. In that section you will see the list of all the modules that are not enabled by default, along with a brief explanation of the module functionality shown at the bottom of the console.

Enabling / disabling a specific module is done with the SpaceBar key. Once you have selected all your needed modules, you should hit the 'q' key in order to go back to the previous menu, and then hit 'Save Changes'. The tool will display that you have enabled certain modules, and it will tell you what are the dependencies that you need to install in order to succesfully compile the modules.

After any changes to the Compilation Flags, you should re-compile & re-install your OpenSIPS.

## Install

In order to install OpenSIPS, go to the sources root folder and run
```bash

make install

```

By default, OpenSIPS will be installed in the / directory.

### Reduce compile time

In order to reduce the compile time of OpenSIPS, one can use the FASTER variable. This functionality leverages multi-core machines by compiling all modules in parallel, using make -jNR_OF_CORES. Note that this method might use a large amount of resources and the number of processes used should be equal or less than the number of cores. Also, this variable suppresses most of the compile output.

For example, in order to install OpenSIPS on a 4 core machine, go to the sources root folder and run
```bash

FASTER=1 make -j4 install

```

### Configuring Install Path

Sometimes, you might want to change the OpenSIPS installation path, due to various reasons ( like having to deploy two OpenSIPS instances on the same machine ).
In order to do that, you should have to use the menuconfig tool.

Run 'make menuconfig' and go to 'Configure Install Prefix'. Then type in your custom OpenSIPS installation directory and hit enter. Then navigate down to 'Save Changes' and hit enter. Afterwards you can do 'make install' again and OpenSIPS will be deployed in your newly configured directory.
