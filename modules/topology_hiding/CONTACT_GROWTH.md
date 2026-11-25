# No-dialog Contact growth finding

The OpenSIPS 3.6 no-dialog topology-hiding path has the same nested growth
pattern as the historical Call-ID codec, but its payload is genuinely binary
and requires a separate wire-format design.

`build_encoded_contact_suffix()` serializes four native `short` lengths, the
route set, the complete incoming Contact URI, flags and the receiving socket.
It XORs that binary record and encodes it as word64 or word32. On a chain, the
incoming Contact URI already contains the previous hop's `thinfo` value, so
each new binary record contains the complete prior encoded record.

The module unit test reproduces five no-dialog layers using an initial
25-character Contact URI, no Record-Route set, flags `0`, the default `thinfo`
parameter and a 14-character socket string. The URI lengths are:

| Layer | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Contact URI length | 25 | 90 | 178 | 294 | 450 | 658 |

Even this minimal case exceeds 255 characters at the third topology-hiding
hop. Route sets and longer advertised sockets make it grow sooner.

## Scope of a separate fix

A Call-ID radix codec cannot be reused because the Contact record begins with
binary length fields and includes flags and socket data. A separate design
should version the Contact wire format and make the chain a list of independently
encoded per-hop segments:

1. Preserve an already-versioned upstream segment list instead of embedding it
   inside the next hop's binary plaintext.
2. Encode only the current hop's route set, previous Contact base URI, flags and
   bind address as a new segment.
3. Append the new segment with an unambiguous URI-safe separator, allowing the
   reverse path to pop exactly one local segment.
4. Retain the current nested representation as the default and as fallback for
   stock/malformed input.
5. Specify bounds and validate all decoded lengths before pointer advancement;
   avoid native-endian `short` fields in the versioned format.
6. Test mixed old/new chains, route sets, passed URI/header parameters, both
   base encodings, requests and replies, and lengths through at least ten hops.

This work should be developed and reviewed independently from the Call-ID
change because it alters the no-dialog state envelope rather than a single
opaque string codec.
