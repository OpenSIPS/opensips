---
title: "Script Operators"
description: "Assignments, string and arithmetic operations can be done directly in the configuration file."
---

Assignments, string and arithmetic operations can be done directly in the configuration file.

## Assignment

Assignments can be done like in C, via '=' (equal) operator. Not that not all variables (from script) can be written, some are read-only. Check with [listing of variables](Script-CoreVar.md) to see which ones can be written too.

```text

$var(a) = 123;
$ru = "sip:user@domain";

```

There is a special assign operator ':=' (colon equal) that can be used with AVPs. If the right value is **null**, all AVPs with that name are deleted. If different, the new value will overwrite any existing values for the AVPs with than name (on other words, delete existing AVPs with same name, add a new one with the right side value).

```text

$avp(val) := 123;

```

## String operations

For strings, '+' is available to concatenate.

```text

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

```text

$var(a) = 4 + ( 7 & ( ~2 ) );

```

> [!NOTE]
> to ensure the priority of operands in expression evaluations do use __parenthesis__.

Arithmetic expressions can be used in condition expressions via test operator ' [ ... ] '.

```text

if( [ $var(a) & 4 ] )
    log("var a has third bit set\n");

```
