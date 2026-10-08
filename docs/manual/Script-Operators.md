---
title: "Script Operators"
description: "Assignments, string and arithmetic operations can be done directly in the configuration file."
---

Assignments, string and arithmetic operations can be done directly in the configuration file.

## Assignment

Assignments can be done as in C, using the `=` (equal) operator. Note that not all script variables can be written; some are read-only. Check the [list of variables](Script-CoreVar.md) to see which ones are writable.

```opensips

$var(a) = 123;
$ru = "sip:user@domain";

```

There is a special assignment operator, `:=` (colon equal), that can be used with AVPs. If the right-hand value is **null**, all AVPs with that name are deleted. Otherwise, the new value overwrites any existing values for AVPs with that name (in other words, it deletes the existing AVPs with the same name and adds a new one with the right-hand value).

```opensips

$avp(val) := 123;

```

## String operations

For strings, '+' is available to concatenate.

```opensips

$var(a) = "test";
$var(b) = "sip:" + $var(a) + "@" + $fd;

```

## Arithmetic and bitwise operations

For numbers, one can use:

* + : plus
* - : minus
* / : divide
* * : multiply
* % : modulo
* | : bitwise OR
* & : bitwise AND
* ^ : bitwise XOR
* ~ : bitwise NOT
* \<< : bitwise left shift
* \>> : bitwise right shift

Example:

```opensips

$var(a) = 4 + ( 7 & ( ~2 ) );

```

> [!NOTE]
> to ensure the priority of operands in expression evaluations do use __parenthesis__.

Arithmetic expressions can be used in condition expressions via test operator ' [ ... ] '.

```opensips

if( [ $var(a) & 4 ] )
    log("var a has third bit set\n");

```
