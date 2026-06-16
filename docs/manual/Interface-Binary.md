---
title: "Binary Internal Interface"
description: "The Binary Internal Interface is an OpenSIPS core interface which offers an efficient way for communication between individual OpenSIPS instances. This is es..."
---

The **Binary Internal Interface** is an OpenSIPS core interface which offers an efficient way for communication between individual OpenSIPS instances. This is especially useful in scenarios where realtime data (such as dialogs) cannot be simply stored in a database anymore, because failover would require entire minutes to complete. This issue can be solved with the new internal binary interface by replicating all the events related to the runtime data (creation / updating / deletion) to a backup OpenSIPS instance.

---

## Configuring the Binary Internal Interface listeners

In order to listen for incoming Binary Packets, a **bin:** interface must be specified.  Its number of listener processes can be tuned with *[tcp_children](https://docs.opensips.org/manual/2-3/script-coreparameters#tcp_accept_aliases)* (default: 8)

```c

   listen = bin:10.0.0.150:5062

   ...

   loadmodule "proto_bin.so"

```

Currently, **dialog** and **usrloc** are the first modules to make use of this interface, and they can now replicate all run-time events (creation/updating/deletion of dialogs/contacts) to one or more OpenSIPS instances. Configuration can be done as follows:

```c

   modparam("dialog", "accept_replicated_dialogs", 1)
   modparam("dialog", "replicate_dialogs_to", "78.46.64.50:5062")

```

More details can be found in the [dialog](../../modules/dialog/README.md#idp3487424) and [usrloc](../../modules/usrloc/README.md#contact_replication) documentation pages.

---

## C Interface Overview (for module developers)

The interface allows the module writer to build and send compact **Binary Packets** in an intuitive way.

In order to **send packets**, the interface provides the following primitives:
* *int bin_init(str *mod_name, int packet_type)* - begins the contruction of a new Binary Packet
* *int bin_push_str(const str *info)* - add a string to the Binary Packet that is currently being built
* *int bin_push_int(int info)* - add an integer to the Binary Packet that is currently being built
* *int bin_send(union sockaddr_union *dest)* - sends the Binary Packet to a given destination over UDP

  

In order to **receive packets**, a module must first register a callback function to the interface:
* *int bin_register_cb(char *mod_name, void (*)(int packet_type))*

  

Each time this callback is triggered, the information can be retrieved in the same order it was written using:
* *int bin_pop_str(str *info)* - retrieve a string from a received Binary Packet
* *int bin_pop_int(void *info)* - retrive an integer from a received Binary Packet
