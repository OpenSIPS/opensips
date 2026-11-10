# Media impairment simulator

`impair.py` applies deterministic Linux `tc netem` profiles for RTP/media regression tests. It is intended for isolated test interfaces, containers, VMs or Linux network namespaces.

## Built-in profiles

- `clean`
- `wifi`
- `4g`
- `congested-4g`
- `bad-mobile`
- `satellite`
- `burst-loss`
- `reorder`

Profiles combine latency, jitter, packet loss, duplication, reordering and bandwidth limits. They are intentionally deterministic configuration presets; repeatability comes from using the same netem configuration for every run.

List the exact settings:

```bash
python3 tools/media-impairment/impair.py profiles
```

## Apply and clear

```bash
sudo python3 tools/media-impairment/impair.py -i eth0 apply --profile congested-4g
sudo python3 tools/media-impairment/impair.py -i eth0 show
sudo python3 tools/media-impairment/impair.py -i eth0 clear
```

Use `--dry-run` to inspect the generated `tc` command without changing the host.

## Network namespaces

For safer automated testing, isolate SIP/RTP traffic in a namespace and shape only its media-facing veth:

```bash
sudo python3 tools/media-impairment/impair.py \
  --namespace media-test \
  --interface veth-media \
  apply --profile bad-mobile
```

The tool invokes `ip netns exec <namespace> tc ...` directly, without shell expansion.

## Custom profile

```json
{
  "delay_ms": 75,
  "jitter_ms": 25,
  "loss_pct": 1.5,
  "duplicate_pct": 0.1,
  "reorder_pct": 0.5,
  "corrupt_pct": 0,
  "rate_kbit": 4000
}
```

Apply it with:

```bash
sudo python3 tools/media-impairment/impair.py -i eth0 apply --config profile.json
```

Percentages are validated in the 0..100 range and interface/namespace names are restricted to safe characters.

## CI usage

A practical media regression job is:

1. start OpenSIPS, RTPengine and endpoints in containers/namespaces;
2. apply one profile to the RTP path;
3. run SIPp/media traffic;
4. capture RTPengine MOS/jitter/loss/RTT through `media_qoe`;
5. evaluate call thresholds through `tools/sipp-ci`;
6. clear the qdisc in the job cleanup step.

For bidirectional impairment, apply a profile to both egress interfaces that carry the two RTP directions. `netem` shapes egress traffic, so one qdisc should not be mistaken for a symmetric network model.


## Safety

By default, `apply` and `clear` refuse to modify a host interface directly.
Use a network namespace for isolated tests:

```bash
sudo python3 tools/media-impairment/impair.py \
  --namespace media-test --interface veth-media apply --profile bad-mobile
```

If host-level shaping is intentional, opt in explicitly with
`--allow-host-interface`. Both `qdisc replace` and `qdisc del` can replace
or remove an existing root queue discipline, so this flag should not be used
casually on production interfaces.
