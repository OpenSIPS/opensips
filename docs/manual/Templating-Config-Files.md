---
title: "Templating opensips.cfg Files"
description: "OpenSIPS 3.0+ releases offer script writers full support for piping the opensips.cfg file (including any other files imported by it) to a generic preprocessi..."
---

## Generic Preprocessing Support

OpenSIPS 3.0+ releases offer script writers full support for piping the *opensips.cfg* file (including any other files imported by it) to a generic preprocessing command.  This may be useful in scenarios where *opensips.cfg* must be parameterized (e.g. listening interfaces, ports, DB connectors, etc.) and deployed to multiple servers, in an automated fashion.  The system administrator may achieve this using the "-p `<cmdline>`" (preprocessor) option.  For example:

```text

opensips -f opensips.cfg -p /bin/cat

```

... is a basic use of the "-p" option, by supplying it with an "echo" preprocessor that receives input via **standard input** and mirrors it to **standard output**.  From here, it's just a matter of choosing a templating language which fits the deployment requirements.  Some basic substitutions can be done using, for example, *sed*:

```bash

opensips -f opensips.cfg -p "/bin/sed s/PRIVATE_IP/10.0.0.10/g"

```

## Common Templating Languages + Examples

Below are some examples of using more advanced templating languages on top of opensips.cfg, for cases where the target environment requires complex decision-making (if statements which enable/disable features, for loops over multiple listening interfaces, etc.).

### GNU m4

[GNU m4](https://www.gnu.org/software/m4/) is a simplistic preprocessor with a mild learning curve, equipped with textual substitution, if statements and file includes among the most notable features.  Here is an example integration with *opensips.cfg*:

```c

listen = udp:PRIVATE_IP:5060
loadmodule "proto_udp.so"

```
**opensips.cfg.m4**

  

```text

divert(-1)
define(`PRIVATE_IP', `127.0.0.1')
divert(0)dnl

```
**env.m4**

  

... and we start OpenSIPS using the below command, which will pipe *opensips.cfg.m4* to ''m4**s standard input, and then read the resulting file from its standard output:**

```text

opensips -f opensips.cfg.m4 -p "m4 env.m4 -"

```

### Jinja2

[Jinja2](http://jinja.pocoo.org/docs/2.10) is a modern templating language with a rich feature set, including textual replacement, if statements, for loops, a plethora of filters, file includes, and the list goes on!  Unlike *m4*, Jinja2 does not currently have a standalone binary, rather it is provided via a Python package.  Here is a way of integrating it with *opensips.cfg*:

  

First, install the **jinja2** Python module with: **"pip install jinja2"**.  Next, prepare the files:

  

```c

listen = udp:{{ private_ip }}:5060
loadmodule "proto_udp.so"

```
**opensips.cfg.j2**

  

```text

import sys
import json
from jinja2 import Template

t = Template("".join(sys.stdin.readlines()))

with open('env.json') as f:
    print(t.render(json.load(f)))

```
**opensips-preproc.py**

  

```text

{
    "private_ip": "127.0.0.1"
}

```
**env.json**

  

... and we start OpenSIPS using:

```text

opensips -f opensips.cfg.j2 -p "python opensips-preproc.py"

```

### Embedded Ruby

[Embedded Ruby (ERB)](https://ruby-doc.org/stdlib-2.6.1/libdoc/erb/rdoc/ERB.html) provides an easy to use, powerful templating system for Ruby. Using ERB, actual Ruby code can be added to any plain text document for the purposes of generating document information details and/or flow control.  Let's see how it integrates with *opensips.cfg*!

  

First, install the ERB package (for Debian/Ubuntu: **"apt install ruby-ejs"**).  Next, prepare the files:

  

```c

listen = udp:<%= private_ip %>:5060
loadmodule "proto_udp.so"

```
**opensips.cfg.erb**

  

```text

#!/usr/bin/env ruby
require 'erb'
require './env.rb'

template = ERB.new($stdin.read, nil, '-')
$stdout.write template.result($erb_context)

```
**~/src/opensips-preproc.rb**

  

```text

$erb_context = binding
private_ip   = '127.0.0.1'

```
**env.rb**

  

... and OpenSIPS is now started using:

```text

opensips -f opensips.cfg.erb -p "ruby opensips-preproc.rb"

```

## Debugging Preprocessor Output

Since the output of the preprocessor is never written to any file and is just consumed by OpenSIPS on each run, script developers may still visualize and debug the generated file during development by using a wrapper script over the preprocessing command such as the following:

```bash

#!/bin/bash
  
m4 env.m4 - | tee >(grep -v __OSSPP_ >/tmp/opensips.cfg)

```
**~/src/preprocessor.sh**

  

... and now we start OpenSIPS using:

```text

opensips -f opensips.cfg.m4 -p ~/src/preprocessor.sh

```

  

The same technique can be used for any other preprocessor.
