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
```opensips

    route {
        route(my_logic);
        switch($retcode)
        {
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
        switch($rU)
        {
            case "101":
                log("destination number is 101\n");
            break;
            case "102":
                log("destination number is 102\n");
            break;
            case "103":
            case "104":
                log("destination number is 103 or 104\n");
            break;
            default:
                log("unknown destination number\n");
       }
    }

    route[my_logic]{
        if(is_method("INVITE"))
        {
            return(-1);
        };
        if(is_method("REGISTER"))
            return(1);
        }
        if(is_method("SUBSCRIBE"))
            return(2);
        }
        if(is_method("NOTIFY"))
            return(3);
        }
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
    while($var(i) < 10)
    {
        xlog("counter: $var(i)\n");
        $var(i) = $var(i) + 1;
    }

```
