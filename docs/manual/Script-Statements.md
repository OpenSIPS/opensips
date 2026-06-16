---
title: "Script Statements"
description: "Statements you can use in the OpenSIPS config file while building the routing logic."
---

Statements you can use in the **OpenSIPS** config file while building the routing logic.

## if

IF-ELSE statement

Prototype:

```text

    if (expr) {
       actions;
    } else {
       actions;
    }

```

The 'expr' should be a valid logical expression.

The logical operators that can be used in the logical expressions:

* == - equal
* != - not equal
* =~ - regular expression matching  (e.g. `$rU` =~ '^1800*' is "`$rU` begins with 1800" )
* !~ - regular expression not-matching
* \> - greater
* \>= - greater or equal
* \< - less
* \<= - less or equal
* && - logical AND
* || - logical OR
* ! - logical NOT
* [ ... ] - test operator - inside can be any arithmetic expression

Example of usage:

```text

    if ( is_method("INVITE") && $rp==5060 )
    {
        log("this sip message is an invite\n");
    } else {
        log("this sip message is not an invite\n");
    }

```

## switch

SWITCH statement - it can be used to test the value of a pseudo-variable. 

IMPORTANT NOTE: 'break' can be used only to mark the end of a 'case' branch (as it is in shell scripts). If you are trying to use 'break' outside a 'case' block the script will return error -- you must use 'return' there.

Example of usage:
```c

    route {
        route(my_logic);
        switch ($retcode) {
        case -1:
            log("process INVITE requests here\n");
            break;
        case 1:
            log("process REGISTER requests here\n");
            break;
        case 2:
        case 3:
            log("process SUBSCRIBE and NOTIFY requests here\n");
            break;
        default:
            log("process other requests here\n");
       }

        # switch of R-URI username
        switch ($rU) {
        case "101":
            log("destination number is 101\n");
            break;
        case "102":
            log("destination number is 102\n"); # continue with 103 and 104
        case "103":
        case "104":
            log("destination number is 103 or 104\n");
            break;
        default:
            log("unknown destination number\n");
       }
    }

    route [my_logic] {
        if (is_method("INVITE"))
            return(-1);

        if (is_method("REGISTER"))
            return(1);

        if (is_method("SUBSCRIBE"))
            return(2);

        if (is_method("NOTIFY"))
            return(3);

        return(-2);
    }

```

> [!WARNING]
> Take care while using 'return' - 'return(0)' stops the execution of the script.

## while

while statement

Example of usage:
```text

    $var(i) = 0;
    $var(cli) = NULL;
    while ($var(i) < 10) {
        if ($(avp(valid_clis[$var(i)]) == $fU) {
            xlog("matched the From user!\n");
            $var(cli) = $fU;
            break;
        }
        $var(i) = $var(i) + 1;
    }

```

## for each

for each statement - easy iteration over indexed variables or pseudo-variables

Example of usage:
```text

    $avp(arr) = 0;
    $avp(arr) = 1;
    $avp(arr) = 2;
    $avp(arr) = 3;
    $avp(arr) = 4;

    for ($var(it) in $(avp(arr)[*]))
        xlog("array value: $var(it)\n");

    # iterate through all Contact URIs from each Contact header
    for ($var(ct) in $(ct[*]))
        xlog("Contact: $var(ct)\n");

    # iterate through all Via headers of a SIP request
    for ($var(via) in $(hdr(Via)[*]))
        xlog("Found \"Via\" header: $var(via)\n");

    # iterate through all JSON documents returned by a MongoDB query
    cache_raw_query("mongodb:location", "{... find ...}", "$avp(res)");
    for ($json(contact) in $(avp(res)[*])) {
        xlog("Found: $json(contact/phone) $json(contact/email)\n");
        
        if ($json(contact/phone) =~ "^40") {
            xlog("found a cheap destination to dial\n");
            break;
        }
    }

```
