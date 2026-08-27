# Call-ID codec wire format

This document fixes the ordering and interpretation of the symbols used by
`th_callid_encode_scheme`. These details are part of the wire format and must
not be changed for an existing scheme name.

## `xor-word64`

The wire value is:

```text
th_callid_prefix || word64(call_id XOR repeated(th_callid_passwd))
```

This is the historical OpenSIPS representation and is byte-identical to
OpenSIPS 3.6 releases which predate the scheme selector.

## `ff1-alnum62`

The wire value is:

```text
th_callid_prefix || marker || payload
```

The configured prefix must contain only ASCII alphanumeric characters. The
one-byte, cleartext marker identifies version 1 and the payload domain:

| Marker | Meaning |
|---|---|
| `A` | The input contained only radix-62 symbols and was encrypted directly. |
| `B` | The input was ranked in the RFC 3261 Call-ID language, converted to radix 62 and encrypted. |
| `C` | The input used the legacy XOR/word64 fallback. |

The radix-62 alphabet, in numerical order, is:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
```

FF1 uses AES-256, ten rounds, an empty tweak and the forward AES
transformation, following NIST SP 800-38G Revision 1 second public draft. All
length and radix calculations use integer arithmetic. Inputs to FF1 must have
at least four radix-62 digits, giving a domain larger than one million.

The AES key is the first and only 32-byte HKDF-SHA-256 output block, with:

```text
IKM  = the exact th_callid_passwd bytes
salt = "OpenSIPS topology_hiding FF1 key v1"
info = "Call-ID ff1-alnum62"
```

### Structured Call-ID ranking

RFC 3261 defines `callid = word [ "@" word ]`. The `@` is structural rather
than an unrestricted alphabet member: it may occur at most once and may not be
the first or last character.

The ordered radix-85 `word` alphabet is:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.!%*_+`'~()<>:\"/[]?{}
```

For a Call-ID of total length `n`, values without `@` occupy the first `85^n`
ranks. Values with `@` follow, grouped by the separator's zero-based position
`p`, where `1 <= p <= n-2`. After removing `@`, the remaining symbols form the
radix-85 number `W`:

```text
rank(no @) = W
rank(@)    = 85^n + (p - 1) * 85^(n - 1) + W
domain(n)  = 85^n + max(n - 2, 0) * 85^(n - 1)
```

The rank is represented by the shortest fixed-width radix-62 string capable of
representing `domain(n)`. Leading zero digits are retained. Since the encoded
width grows strictly with `n`, the decoder recovers `n` from that width, then
unranks the value and restores `@` in its original position.

### Bounds and fallback

FF1 processing is bounded at 4096 input or ciphertext characters. Longer,
shorter-than-domain, or non-compliant inputs use marker `C` and the historical
XOR/word64 codec. A decoder rejects unknown markers, non-radix-62 ciphertext,
invalid structured ranks and malformed word64 padding.

The format provides confidentiality but not integrity. Scheme, password or
prefix changes require active dialogs to be drained.
