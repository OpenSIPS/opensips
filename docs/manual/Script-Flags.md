---
title: "Script Flags"
---

## What are the flags?

A flag is a TRUE or FALSE entity. The flags are 32 in number, for each type (see below). A flag is identified by its name - again, you cannot have more than 32 different names/flags. You do not have to declare or define the names of the flags, just use them.
The flags may be used for whatever purpose, there is nothing pre-defined.

## Types of flags

* **message flags** (or transaction flags) these flags are attached to the current SIP message or to the current transaction (if a transaction exists). So these flags are transaction persistent. They are visible in all routes and cases where the transaction or SIP message context is visible.
* **branch flags**  these flags are also at transaction level, but per SIP branch - yeah SIP branch has its own set of flags. Each time in the context of a specific SIP branch (like in `branch_route` or `reply_route`), you will see the matching branch flags. These flags may be operated from script level or by various module functions (like usrloc saving the branch flags for each registered contact).
* **script flags**  are no-message-related flags - they are only script persistent and you can strictly use them for scripting. Once you exit a top level route, they will be lost. These flags are useful and they offer an option to de-congest the message flags - many flags have no need to be saved as they just reflect some scripting status.

---

## Script Flag Functions

There are a bunch a functions that helps into working with the flags from script level - to set, reset and check.

### Message/transaction flags

* setflag(FLAG)
* resetflag(FLAG)
* isflagset(FLAG)

*Examples: setflag(accounting), resetflag(DO_NAT) or setflag(1942)*

### Branch flags

* setbflag(branch_idx, FLAG)
* resetbflag(branch_idx, FLAG)
* isbflagset(branch_idx, FLAG)

  

or, the shorter format, working on the default (branch 0) flags:

* setbflag(FLAG)
* resetbflag(FLAG)
* isbflagset(FLAG)

### Script flags

* setsflag/setscriptflag(FLAG)
* resetsflag/resetscriptflag(FLAG)
* issflagset/isscriptflagset(FLAG)

---

## Flags related Variables

### Message/transaction flags

`$mf` - ReadOnly; outputs a list of flags

### Branch flags

`$bf` - ReadOnly; returns a list of flags

### Script flags

`$sf` - ReadOnly; outputs a list of flags

---

## Flags and routes

### Message/transaction flags

These flags will show up in all routes where messages related to the initial request are processed. So, they will be visible and changeable in `onbranch`, `failure` and `onreply` routes; the flags will be visible in all `branch` routes; if you change a flag in a `branch` route, the next `branch` routes will inherit the change.

### Branch flags

These flags will show up in all routes where messages related to initial branch request are processed. So, in `branch` route you will see different sets of flags (as they are different branches); in `onreply` route you will see the branch flags corresponding to the branch the reply belongs to; in `failure` route, the branch flags corresponding to the branch the winning reply belongs to will be visible.
In `request` route, you may have multiple branches (as a result of a `lookup()` for example), but at least one. All the time there is the default branch, index 0, corresponding to the RURI. Any additional branches will get indexes from 1 and above.

### Script flags

There flags are available only in script and are reset after each top level route execution (routes internally triggered by OpenSIPS). They will be persistent per main route, onreply_route, branch_route, failure_route. Note they will be inherit in routes called from other routes.

---

## Example

### NAT flag handling

```c

 ..........
 # 3 - the nat flag
 modparam("usrloc", "nat_bflag", "NAT_BFLAG")
 ..........
 
 route {
   ..........
   if (nat detected)
      setbflag(NAT_BFLAG); # set branch flag "NAT_BFLAG" for the branch 0

   ..........
   if (is_method("REGISTER")) {
      # the branch flags (including "NAT_BFLAG") will be saved into location
      save("location");
      exit;
   } else {
      # lookup will load the branch flag from location
      if (!lookup("location")) {
         sl_send_reply("404","Not Found");
         exit;
      }
      t_on_branch("1")
      t_relay();
   }
 }
 
 branch_route[1] {
   xlog("-------branch=$T_branch_idx, branch flags=$bF\n");
   if (isbflagset(NAT_BFLAG)) {
      #current branch is marked as natted
      .........
   }
 }

```

if no parallel forking is done, you can get rid of the branch route and add instead of t_on_branch():
```text

   ........
   if (isbflagset(NAT_BFLAG)) {
      #current branch is marked as natted
      .........
   }
   ......... 

```
