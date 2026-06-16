---
title: "Known Issues"
description: ""
---

* **cflags column in usrloc location table**
  * when *adding*/*removing*/*changing the first appearance order* of **branch flags** in the OpenSIPS script, followed by a proxy restart (and a complete location table reload), the bflag bitmasks (the *cflags* column) of all the contact in the *location* table will no longer be consistent with the new representation.
  * as a workaround to this, the table must be truncated before restarting OpenSIPS with the new script.
