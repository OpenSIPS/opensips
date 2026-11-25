---
title: "media_security Module"
description: "Audit and enforce ICE, STUN/TURN candidate, DTLS-SRTP and RTCP-mux policy in SDP."
---

## Admin Guide

### Overview

`media_security` validates media-security negotiation carried in SDP. OpenSIPS remains the SIP signaling plane; ICE connectivity checks, STUN/TURN allocation and SRTP packet processing belong in the media endpoint/relay (for example RTPengine). This module makes those negotiations enforceable and observable at the SIP layer.

It detects:

- ICE credentials and candidates
- server-reflexive (`typ srflx`) candidates learned through STUN
- relay (`typ relay`) candidates allocated through TURN
- DTLS fingerprint and setup attributes
- secure RTP profiles (`RTP/SAVP*` / `UDP/TLS/RTP/SAVP*`)
- SDES `a=crypto`
- `a=rtcp-mux`

Policy is evaluated per active RTP `m=` section. Session-level ICE,
fingerprint and setup attributes are inherited by RTP media according to SDP
rules, while media-level attributes do not leak into sibling media sections.
`a=rtcp-mux` must be present for every active RTP media section when
required. Non-RTP sections such as WebRTC data channels, and rejected
`m=` sections using port 0, do not make RTP security checks fail.

The classification is fail-closed:

- transport protocol tokens are matched case-insensitively, and every
  active `audio`/`video` section is treated as RTP media, even with a
  missing or non-RTP transport token;
- port 0 sections carrying `a=bundle-only` (RFC 8843) are considered
  active;
- `a=candidate` and `a=crypto` are only taken into account inside active
  media sections, as both are media-level attributes;
- if the message carries several `application/sdp` body parts (e.g.
  `multipart/alternative`), every part must satisfy the policy, and
  `media_security_has()` only reports features present in all parts.
  If there is no SDP body at all, the checks fail.

### Parameters

#### require_ice

Require valid effective `a=ice-ufrag` and `a=ice-pwd` credentials for every
active RTP media section. Session-level credentials are inherited unless a
media section supplies its own values. The values must follow the RFC 8839
grammar: 4 to 256 (ufrag) and 22 to 256 (pwd) characters out of letters,
digits, `+` and `/`. Default: `1`.

#### require_dtls_srtp

Require a valid DTLS fingerprint, a valid `setup` role (`active`, `passive`,
`actpass` or `holdconn`) and a DTLS-SRTP profile (`UDP/TLS/RTP/SAVP` or
`UDP/TLS/RTP/SAVPF`) for every active RTP media section. Session-level
fingerprint/setup values are inherited by media sections. Default: `1`.

A fingerprint is valid if its hash function is one of `sha-1`, `sha-224`,
`sha-256`, `sha-384` or `sha-512` (case-insensitive) and its value consists
of colon-separated hex byte pairs of exactly that digest's length. MD2, MD5
and unknown hash functions are not accepted.

#### require_rtcp_mux

Require `a=rtcp-mux` in every active RTP media section. Default: `1`.

#### require_turn_relay

Require at least one ICE candidate with `typ relay` in an active media
section. This is useful for deployments which must prove TURN reachability, but is disabled by default because a direct or server-reflexive path is normally valid. Default: `0`.

#### allow_sdes

Allow SDES-SRTP to satisfy the secure-media requirement when DTLS-SRTP is absent. With SDES allowed, each active RTP media section must be keyed either by DTLS-SRTP or by SDES, i.e. use `RTP/SAVP` or `RTP/SAVPF` with at least one `a=crypto:<tag> <suite> inline:<key>` attribute. Default: `0`.

#### emit_compliant

Raise a success event for compliant SDP in addition to violation events. Default: `0`.

### Functions

#### media_security_check()

Apply the policy configured through module parameters. Returns `1` on success and `-1` on violation.

```opensips
if (has_body("application/sdp") && !media_security_check()) {
    send_reply(488, "Media security policy failed");
    exit;
}
```

#### media_security_profile(profile)

Apply a predefined policy:

- `webrtc` — ICE + DTLS-SRTP + RTCP mux
- `webrtc-turn` — same as `webrtc`, plus a TURN relay candidate
- `sdes` — secure RTP with SDES allowed
- `secure` — DTLS-SRTP, optionally SDES if `allow_sdes=1`

```opensips
if (!media_security_profile("webrtc")) {
    send_reply(488, "WebRTC media requirements not met");
    exit;
}
```

#### media_security_has(feature)

Probe one SDP capability. Supported names are `ice`, `candidate`, `srflx`, `relay`, `dtls-srtp`, `sdes`, `rtcp-mux`, and `srtp`.

### RTPengine integration

This module does not replace RTPengine. A typical WebRTC/SIP deployment uses RTPengine to terminate or bridge ICE/DTLS-SRTP and uses `media_security` to verify the resulting policy at the signaling boundary.

The existing `rtpengine_offer()` and `rtpengine_answer()` calls may continue passing RTPengine media flags. OpenSIPS intentionally passes unknown RTPengine options through to the daemon, so deployments can use the ICE/DTLS/SRTP features supported by their installed RTPengine version while keeping policy checks version-independent.

### Events

#### E_MEDIA_SECURITY_VIOLATION

Raised when policy validation fails. Event parameters include:

- `reason`
- `ice`
- `candidate`
- `stun_srflx`
- `dtls_srtp`
- `rtcp_mux`
- `relay_candidate`
- `sdes`

Reasons include `no-sdp`, `ice-required`, `dtls-srtp-required`, `rtcp-mux-required`, and `turn-relay-candidate-required`.

#### E_MEDIA_SECURITY_COMPLIANT

Raised for successful checks when `emit_compliant=1`.

### Statistics

- `media_security:checks`
- `media_security:violations`
- `media_security:ice_sdps`
- `media_security:ice_candidate_sdps`
- `media_security:stun_srflx_sdps`
- `media_security:dtls_srtp_sdps`
- `media_security:turn_relay_sdps`
- `media_security:sdes_sdps`
- `media_security:rtcp_mux_sdps`

The existing Prometheus module can export these counters without an additional exporter.
