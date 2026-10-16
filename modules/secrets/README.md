---
title: "secrets Module"
description: "Load sensitive configuration values from environment variables, files, HashiCorp Vault and Kubernetes Secrets without placing secret values in opensips.cfg."
---

## Admin Guide

### Overview

The `secrets` module separates sensitive values from the OpenSIPS routing script. A named secret is configured as a provider reference and exposed through the read-only `$secret(name)` pseudo-variable.

Secret values are never returned by MI commands and are not logged by the module.

Supported providers:

- `env://VARIABLE`
- `file:///path/to/file`
- `vault://host:8200/v1/secret/data/path#field`
- `vault+http://host:8200/v1/secret/data/path#field`
- `vault+https://host:8200/v1/secret/data/path#field`
- `k8s://namespace/secret-name#key`
- `k8s://secret-name#key` (uses the Pod service-account namespace)

Vault KV v1 and KV v2 response layouts are supported. A dotted field path may be used after `#`, for example `#credentials.password`.

### Dependencies

The module requires libcurl for Vault and Kubernetes API requests.

For `k8s://`, the default in-cluster configuration uses
`KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT_HTTPS` and the standard
service-account token/CA/namespace files mounted under
`/var/run/secrets/kubernetes.io/serviceaccount/`. The Pod service account
must have RBAC permission to `get` the referenced Secret.

### Exported Parameters

#### secret

Defines a named secret. The parameter can be repeated.

```opensips
modparam("secrets", "secret", "db_password=env://DB_PASSWORD")
modparam("secrets", "secret", "tls_password=file:///run/secrets/tls_password")
modparam("secrets", "secret", "rating_token=vault://vault.service:8200/v1/secret/data/opensips#token")
modparam("secrets", "secret", "carrier_password=k8s://telephony/opensips-carrier#password")
```

#### allow_missing

If `0` (default), startup fails when a configured secret cannot be loaded. If set to `1`, missing values remain unavailable and may be reloaded later.

#### vault_timeout

Vault request (and connect) timeout in seconds. Default: `5`.

#### vault_scheme

Scheme used for `vault://` references, either `https` or `http`. Default: `https`. Use the explicit `vault+http://` form for an intentionally unencrypted endpoint. Setting `http` requires `allow_insecure_vault_http`.

#### allow_insecure_vault_http

If `0` (default), Vault is only queried over HTTPS, and both `vault_scheme=http` and `vault+http://` definitions are rejected. Set to `1` only for trusted test networks. Default: `0`.

HTTPS server certificates are always verified, against the system CA bundle used by libcurl.

#### vault_token_env

Environment variable holding the Vault token. Default: `VAULT_TOKEN`.

#### vault_namespace_env

Optional environment variable holding an `X-Vault-Namespace` value. Default: `VAULT_NAMESPACE`.


#### k8s_timeout

Kubernetes API request timeout in seconds. Default: `5`.

#### k8s_api

Optional explicit Kubernetes API base URL, for example
`https://kubernetes.default.svc:443`. If unset, the module builds the
in-cluster URL from the standard Kubernetes service environment variables.

#### k8s_token_file

Path to the service-account bearer token. Default:
`/var/run/secrets/kubernetes.io/serviceaccount/token`.

#### k8s_ca_file

CA bundle used to verify the Kubernetes API server. Default:
`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.

#### k8s_namespace_file

Namespace file used by the short `k8s://secret-name#key` form. Default:
`/var/run/secrets/kubernetes.io/serviceaccount/namespace`.

### Exported Pseudo-Variable

#### $secret(name)

Returns the current value of the named secret or NULL when unavailable. The variable is read-only.

Note that any value read into the script can still be printed by the script itself (e.g. by `xlog()`), so avoid logging `$secret()` or variables holding it.

```opensips
$var(auth) = $secret(rating_token);
```

Dynamic PV names are supported in the same manner as other named pseudo-variables:

```opensips
$var(name) = "rating_token";
$var(auth) = $secret($var(name));
```

### Exported Functions

#### secret_exists(name)

Returns true when the named secret exists and currently has a loaded value.

### Exported MI Functions

#### secrets:reload

Reload every configured secret from its provider. The reload is atomic: if any provider fails, no value is replaced and an error is returned. With `allow_missing=1`, a secret that cannot be loaded at all therefore makes every full reload fail; use `secrets:reload_one` for the remaining secrets until it is fixed.

```bash
opensips-cli -x mi secrets:reload
```

#### secrets:reload_one

Reload a single named secret.

```bash
opensips-cli -x mi secrets:reload_one name=rating_token
```

#### secrets:list

Lists secret names, provider types and loaded state. Values and provider source details are deliberately omitted.

### Exported Statistics

- `secrets:loaded`
- `secrets:reload_failures`

### Operational notes

File-based providers work directly with Docker/Kubernetes mounted Secret volumes. `secrets:reload` can be called after an atomic Secret-volume update without restarting OpenSIPS. Only regular files (or symlinks to regular files, as used by Secret volumes) of at most 1 MiB are accepted; trailing CR/LF characters are removed. Files must be readable by the user OpenSIPS runs as.

Providers are only queried at startup (before the worker processes are forked) and from the MI process handling a reload, so SIP worker processes never block on file or network I/O; they only read the cached values from shared memory. An MI reload may block its MI process for up to the configured timeout per network secret.

Vault fields and Kubernetes keys must hold string values; other JSON types are rejected.

The Kubernetes API provider reads the Secret object over HTTPS using the Pod
service account and decodes the selected `data[key]` value from base64.
Kubernetes keys and Vault JSON field-path components are matched
case-sensitively, consistent with JSON/Secret key semantics. The
module never exposes the bearer token or Secret value through MI.

For Vault, prefer short-lived scoped tokens supplied through the configured token environment variable, and TLS endpoints in production.


### Kubernetes naming validation

The provider validates each component using the Kubernetes rule which actually
applies to it:

- namespace: RFC 1123 DNS label (lowercase alphanumeric or `-`, max 63)
- Secret object name: RFC 1123 DNS subdomain (lowercase alphanumeric, `-`
  and `.`, max 253, with valid labels)
- Secret `data` key: alphanumeric plus `-`, `_` or `.`

This avoids both accepting invalid API paths and incorrectly rejecting valid
Secret keys such as `tls.crt` or `DB_PASSWORD`.


### Vault transport safety

Vault uses HTTPS by default. Plain HTTP is rejected unless
`allow_insecure_vault_http=1` is explicitly configured. This opt-in applies
both to `vault_scheme=http` and to individual `vault+http://...`
definitions.

Provider HTTP responses, parsed JSON string values, rotated secret buffers and
temporary file/token buffers are zeroed before they are released where the
module owns the storage.
