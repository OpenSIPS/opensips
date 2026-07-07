---
title: "Script Flags"
description: "Starting from OpenSIPS 1.9, flags may receive alphanumerical values. However, this does not affect performance, since they are converted into bit indexes upo..."
---

## Types of flags

* **message flags** (or transaction flags) these flags are transaction persistent. They are visible in all routes and cases where the transaction context is visible
* **branch flags**  are saved also in transaction, but per branch; also they will be saved in usrloc (per contact). A new set of functions were added for manipulating these flags from script. So, there flags will be registration persistent and branch persistent.

---

## Corresponding Functions

Starting from OpenSIPS 1.9, **flags may receive alphanumerical values**. However, this does not affect performance, since they are converted into bit indexes upon startup. When it comes to DB persistency (only a few modules do this - e.g. usrloc), flags are generally stored in their string form, in order to preserve their semantics, and not the bit index they received during a given OpenSIPS run.

### Message/transaction flags

* setflag(FLAG)
* resetflag(FLAG)
* isflagset(FLAG)

*Examples: setflag(accounting), resetflag(DO_NAT) or setflag(19)*

### Branch flags

* setbflag/setbranchflag(branch_idx, FLAG)
* resetbflag/resetbranchflag(branch_idx, FLAG)
* isbflagset/isbranchflagset(branch_idx, FLAG)

  

or, the shorter format, working on the default (branch 0) flags:

* setbflag(FLAG)
* resetbflag(FLAG)
* isbflagset(FLAG)

---

## Flags and Pseudo Variables

### Message/transaction flags

`$mf` - ReadOnly; outputs a list of flags

### Branch flags

`$bf` - ReadOnly; returns a list of flags

---

## Flags and routes

### Message/transaction flags

These flags will show up in all routes where messages related to the initial request are processed. So, they will be visible and changeable in onbranch, failure and onreply routes; the flags will be visible in all branch routes; if you change a flag in a branch route, the next branch routes will inherit the change.

### Branch flags

There flags will show up in all routes where messages related to initial branch request are processed. So, in branch route you will see different sets of flags (as they are different branches); in onreply route yo will see the branch flags corresponding to the branch the reply belongs to; in failure route, the branch flags corresponding to the branch the winning reply belongs to will be visible.
In request route, you can have multiple branches (as a result of a lookup(), enum query, append_branch(), etc) - the default branch is 0 (corresponding to the RURI); In reply routes there will be only one branch , the 0 one. In branch route the default branch is the current process branch (having index 0); In failure route, initially there is only one branch (index 0), corresponding the failed branch.

---

## Example

### Nat flag handling

```opensips

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
