---
title: "media_qoe Module"
description: "Turn RTPengine media-quality statistics into OpenSIPS events, thresholds and monitoring statistics."
---

## Admin Guide

### Overview

The `media_qoe` module converts RTPengine call-quality values into operational OpenSIPS signals. It is intentionally decoupled from the RTPengine control protocol: the existing `rtpengine` module remains responsible for querying media statistics and the script feeds the selected values to `media_qoe`.

This keeps the module usable with the existing `$rtpstat(...)` interface and avoids issuing a second RTPengine query.

### RTCP and SRTCP architecture

OpenSIPS is the SIP signaling plane and does not terminate RTP/RTCP packets. RTPengine remains the media plane for RTP/RTCP and, when secure media is negotiated, SRTP/SRTCP. Its RTCP-derived measurements are exposed by the existing OpenSIPS `rtpengine` module as MOS, jitter, packet-loss and round-trip values; `media_qoe` turns those measurements into thresholds, events and monitoring statistics.

This split avoids duplicating an RTP/RTCP stack inside OpenSIPS.

### Parameters

#### min_mos

Minimum acceptable MOS in RTPengine MOS units. RTPengine exposes MOS as an integer from 0 to 50, so `35` represents MOS 3.5. Default: `35`.

Set to a negative value to disable MOS degradation checks.

#### max_jitter

Maximum acceptable `jitter-average` value. Default: `-1` (disabled).

#### max_packetloss

Maximum acceptable `packetloss-average` value. Default: `-1` (disabled).

#### max_roundtrip

Maximum acceptable `roundtrip-average` value. Default: `-1` (disabled).

RTPengine reports these QoE fields in fixed units: jitter in milliseconds,
round-trip time in microseconds, packet loss as a percentage, and MOS in tenths
(`35` = 3.5). The non-MOS thresholds are disabled by default so deployments
can choose policy values explicitly.

#### emit_updates

Raise `E_MEDIA_QOE_UPDATE` for non-final reports. Default: `1`.

### Functions

#### media_qoe_report(callid, mos, jitter, packetloss, roundtrip)

Records an intermediate quality sample. The Call-ID must be non-empty. Numeric metrics must be non-negative integers, MOS must be in `0..50`, and
packet loss must be in `0..100` percent.

RTPEngine may legitimately return no value for RTCP-derived statistics on a
short call or when endpoint RTCP reports are unavailable. Empty, `null`, `<null>`
and `n/a` metric values are therefore treated as **unavailable**, not invalid.
Unavailable metrics do not participate in threshold evaluation and increment
`incomplete_reports`. Malformed numeric values still return a negative value
and increment `invalid_reports`.

Returns `1` when the sample is within configured thresholds and `2` when it
is degraded.

#### media_qoe_final(callid, mos, jitter, packetloss, roundtrip)

Records the final quality sample and raises `E_MEDIA_QOE_FINAL`.

### RTPengine example

The existing RTPengine module already exposes the values required by this module:

```opensips
media_qoe_report(
    $ci,
    "$rtpstat(MOS-average)",
    "$rtpstat(jitter-average)",
    "$rtpstat(packetloss-average)",
    "$rtpstat(roundtrip-average)"
);
```

At the end of a call, the same values can be submitted as a final sample:

```opensips
media_qoe_final(
    $ci,
    "$rtpstat(MOS-average)",
    "$rtpstat(jitter-average)",
    "$rtpstat(packetloss-average)",
    "$rtpstat(roundtrip-average)"
);
```

The `$rtpstat` variables are quoted on purpose: `$rtpstat` returns NULL
when RTPengine has no value for a statistic, and OpenSIPS refuses to pass a
bare NULL variable as a string parameter, so the whole function call would
fail. Inside a quoted string a NULL value is rendered as `<null>`, which
`media_qoe` treats as an unavailable metric.

For per-leg or more granular media data, the script may derive values from `$rtpquery` and pass them to the same functions.

### Events

#### E_MEDIA_QOE_UPDATE

Raised for intermediate samples when `emit_updates=1`. It carries the same
`callid`, `mos`, `jitter`, `packetloss` and `roundtrip` parameters as
`E_MEDIA_QOE_DEGRADED`; `reason` is only present when the sample is degraded.

#### E_MEDIA_QOE_DEGRADED

Raised whenever at least one **available** configured metric violates its threshold. Parameters:

- `callid`
- `mos`
- `jitter`
- `packetloss`
- `roundtrip`
- `reason` (`mos`, `jitter`, `packetloss` or `roundtrip`; only the first
  violated threshold, checked in this order, is reported)

Unavailable metric values are emitted as the string `null`.

#### E_MEDIA_QOE_FINAL

Raised for final samples and contains the same media fields. If the final sample is degraded, a `reason` parameter is included as well.

### Statistics

- `media_qoe:reports`
- `media_qoe:invalid_reports`
- `media_qoe:incomplete_reports`
- `media_qoe:degraded_reports`
- `media_qoe:final_reports`
- `media_qoe:last_mos`
- `media_qoe:last_jitter`
- `media_qoe:last_packetloss`
- `media_qoe:last_roundtrip`
- `media_qoe:last_available_mask`

The availability mask disambiguates an unavailable RTPengine value from a real
zero: bit 0 = MOS, bit 1 = jitter, bit 2 = packet loss, bit 3 = round-trip.
For example, `15` means all four values in the `last_*` snapshot are
available.

These statistics are immediately available to the existing Prometheus module, while the events can be consumed by event routes, external event transports or observability pipelines.
