---
title: "config_tx Module"
description: "Stage, commit and roll back OpenSIPS routing configuration changes with conflict detection and atomic file replacement."
---

## Admin Guide

### Overview

OpenSIPS already validates a route reload across all script processes before switching to the new route set. The `config_tx` module adds the missing deployment layer around that mechanism:

- stage a candidate routing configuration without touching the active file;
- optionally validate the exact staged bytes with a separate `opensips -C` process;
- inspect a safe diff summary before commit;
- remember the active-file hash at staging time;
- reject commits if the active file changed in the meantime;
- atomically replace the active file using `rename(2)`;
- invoke the existing all-process `reload_routing_script()` validation/switch path;
- restore the previous file automatically if validation fails;
- retain the previous successful configuration for explicit rollback.

The active `cfg_file` path must be a regular file, not a symbolic link.
Atomic rename replaces a directory entry rather than a symlink target, so
refusing symlinks avoids silently breaking configuration-management links.
When `fsync_changes=1`, the module fsyncs both the temporary file and the
parent directory after rename for crash durability.

This module only manages the file-backed OpenSIPS **routing** configuration.
It does not hot-reload module parameters, listeners, loaded modules or other
core settings that OpenSIPS itself cannot reload at runtime. A candidate may
pass full `opensips -C` validation while containing non-route changes; those
changes are persisted to disk but do not become active until a normal restart.
For rolling route deployments, keep transactions limited to route logic and
route includes.

Relative paths (the `-f` configuration file given at startup and the `path`
argument of `config_tx:stage`) are resolved against the directory OpenSIPS was
started from, the same way the core `reload_routes` command does, since
OpenSIPS changes its working directory when it daemonizes.

### Dependencies

#### OpenSIPS Modules

None.

#### External Libraries or Applications

None. The OpenSIPS user must be allowed to create files in the directory of
the active configuration file (temporary validation and replacement files are
created next to it) and, if the configuration file is owned by another user
or group, to change the ownership of those files back to the original one
(otherwise commit/rollback fail and leave the active file untouched).

### Exported Parameters

#### max_config_size (integer)

Maximum staged configuration file size in bytes. Default: `8388608` (8 MiB).

#### fsync_changes (integer)

Call `fsync()` on the temporary file before the atomic rename and on the
parent directory after it. Default: `1`.

#### validate_on_stage (integer)

Run full OpenSIPS configuration validation on the staged bytes before they are
accepted. Default: `1`.

Validation writes the exact candidate snapshot to a temporary file adjacent to
the active configuration and executes:

```
opensips -C -f <temporary-file>
```

Using a separate process keeps parser/module initialization state isolated from
the running OpenSIPS instance.

#### validate_on_commit (integer)

Repeat external validation immediately before commit. Default: `1`. This
catches environment or dependency changes that happened after staging.

#### validator_binary (string)

Optional executable used for validation. By default the module reuses
`argv[0]`, i.e. the executable that started the current OpenSIPS process,
looked up through `PATH` if it contains no `/` and run from the startup
working directory. This parameter is useful when OpenSIPS was launched
through a wrapper.

### Exported MI Functions

#### config_tx:stage

Stages a candidate file and records the hash of the currently active configuration.

```bash
opensips-cli -x mi config_tx:stage path=/etc/opensips/candidate.cfg
```

The candidate is copied into shared memory, so subsequent modification or
deletion of the candidate source file does not alter the staged transaction.
With `validate_on_stage=1`, the snapshot must first pass `opensips -C`.

#### config_tx:validate

Explicitly validates the currently staged bytes with the external OpenSIPS
validator and returns `valid=true/false` plus the validator binary used.

```bash
opensips-cli -x mi config_tx:validate
```

#### config_tx:diff

Returns a bounded diff summary without copying configuration contents through
MI:

- active, base and staged hashes;
- whether the active file changed since staging;
- active/staged byte counts and byte delta;
- active/staged line counts and line delta;
- the first line whose bytes differ.

```bash
opensips-cli -x mi config_tx:diff
```

This is intentionally a summary rather than a full unified diff, so large
routing scripts or embedded secrets are not exposed through the management
interface.

#### config_tx:status

Returns:

- whether a candidate is staged;
- active and staged version numbers;
- active configuration hash;
- staged byte/line counts;
- staged hash;
- base hash captured at stage time;
- rollback availability/hash.

```bash
opensips-cli -x mi config_tx:status
```

#### config_tx:commit

Commits the staged configuration only if the active config still matches the base hash captured by `stage`.

```bash
opensips-cli -x mi config_tx:commit
```

Commit sequence:

1. optionally repeat full `opensips -C` validation of the staged bytes;
2. re-read and hash the active file;
3. reject with HTTP-style MI code `409` if it changed since staging;
4. atomically install the staged bytes;
5. call the existing OpenSIPS route reload mechanism;
6. if route validation/reload fails, atomically restore the previous file;
7. distinguish a successful restore from a restore failure that requires manual intervention;
8. on success, retain the previous config as the rollback snapshot.

#### config_tx:rollback

Atomically installs the retained previous successful configuration and runs the standard route reload validation again.

```bash
opensips-cli -x mi config_tx:rollback
```

Rollback first re-reads the active file and compares it with the hash of the
configuration last committed or rolled back by `config_tx`. If another
deployment tool or operator changed the file in the meantime, rollback returns
MI code `409` instead of overwriting that external change. This also applies
after the file was edited by hand and activated with the core `reload_routes`
command: `config_tx` only rolls back changes it made itself.

After a successful rollback, the configuration that was just replaced is retained as the next rollback snapshot, providing a one-step roll-forward.

#### config_tx:discard

Drops the staged candidate without changing the active configuration.

```bash
opensips-cli -x mi config_tx:discard
```

### Exported Statistics

- `config_tx:staged`
- `config_tx:active_version`
- `config_tx:stages`
- `config_tx:commits`
- `config_tx:rollbacks`
- `config_tx:conflicts`
- `config_tx:failures`
- `config_tx:validations`
- `config_tx:validation_failures`

### Concurrency model

A stage captures the hash of the active file. Commit compares that hash again immediately before replacement. The module also tracks the hash of the last configuration it successfully activated, and rollback refuses to proceed if the active file no longer matches it. These checks prevent staged commits or rollbacks from silently overwriting separately deployed config changes.

OpenSIPS' existing reload engine remains responsible for parsing/fixing the new route set in all script-capable processes and only switching routes if all of them validate successfully.


### Concurrent management operations

Mutating operations (`stage`, `commit`, `rollback`, `discard`) are
serialized: while one of them is running, any other mutating request fails
immediately with MI code `409` ("another config_tx operation is in
progress") and may simply be retried. This prevents two MI workers from
committing the same base snapshot concurrently or a new staged candidate from
being cleared by an older commit which was already in progress.

Concurrent requests are rejected rather than queued because a commit or
rollback waits for every OpenSIPS script process to validate the new routes
over IPC; a process blocked waiting for the operation would not answer and
the route reload would time out.

Status, diff, validate and statistics readers only take a short-lived
metadata lock and are never blocked by a running validation or reload.
