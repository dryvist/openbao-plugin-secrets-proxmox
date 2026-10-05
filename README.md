---
type: project
title: OpenBao Proxmox secrets engine
description: OpenBao external secrets engine with leased API tokens for Proxmox VE 9.
tags: [openbao, proxmox, secrets-engine]
timestamp: 2026-10-03T16:52:45Z
---

This project implements dynamic credentials and Gate 3 rotation. It provides a
multiplexed OpenBao plugin, validated connection configuration, role storage,
and renewable leased API tokens. Reading `creds/<name>` creates a
privilege-separated token with its own ACL. OpenBao lease revocation and
expiry delete the token. Writing a role performs validation without creating
Proxmox resources.

See the [implementation plan](docs/implementation-plan.md) for phase boundaries
and acceptance gates. Local OpenBao tests use a TLS API fixture. Live Proxmox
VE 9 acceptance remains pending, so Gate 2 is not yet accepted. Gate 3
management and static-token rotation are available for local testing under
the implementation exception. This is not a production release.

## Build and test

Enter the repository's development shell, then use the standard Go commands:

```sh
nix develop
go build ./cmd/openbao-plugin-secrets-proxmox
go test -race ./...
BAO_TEST_BINARY=bao go test -race -run TestOpenBaoMounts -v .
```

The dependency baseline is Go 1.27, OpenBao SDK/API v2.7.1, and
`github.com/luthermonson/go-proxmox` v0.8.2. The tests cover privilege
separation, ACLs, renewal limits, cleanup retries, provisioning recovery,
management-token replacement, scheduled static rotation, and
management-secret omission. The opt-in OpenBao test builds and registers
the plugin in an isolated, loopback-only development server. It exercises
issuance, renewal, revocation, automatic expiry, parent-token revocation, and
static credential reads and replacement, and two independent mounts against
TLS fixtures. These checks do not establish
live Proxmox behavior.

## Local registration

Use a local OpenBao server configured with a writable `plugin_directory` and
an authenticated `bao` CLI session with permission to register and mount
plugins. Build for the operating system and architecture of that server.
Set `PLUGIN_DIR` to its configured plugin directory before running:

```sh
install -m 0755 ./openbao-plugin-secrets-proxmox \
  "${PLUGIN_DIR:?Set PLUGIN_DIR to the server plugin_directory}/openbao-plugin-secrets-proxmox"
PLUGIN_SHA256="$(sha256sum "$PLUGIN_DIR/openbao-plugin-secrets-proxmox" | cut -d ' ' -f 1)"
bao plugin register -sha256="$PLUGIN_SHA256" \
  secret openbao-plugin-secrets-proxmox
bao secrets enable -path=proxmox openbao-plugin-secrets-proxmox
```

This uses the OpenBao [plugin registration interface](https://openbao.org/docs/plugins/).
The checksum identifies the locally built binary; it is not a release signature.

## Configuration

Write connection settings at `proxmox/config`. Supply secret material through
a protected file. In this example, `PROXMOX_TOKEN_SECRET_FILE` contains the
file path, not the token value. The CLI reads the file using `@file` syntax,
so the token value is not placed in command arguments or shell history.

```sh
bao write proxmox/config \
  endpoint='https://pve.example.com:8006' \
  token_id='manager@pve!openbao' \
  token_secret=@"${PROXMOX_TOKEN_SECRET_FILE:?Set the path to the protected token file}" \
  timeout=30s
bao read proxmox/config
```

Use a token provisioned for your own non-production environment. The example
endpoint and identities are placeholders.

| Field | Meaning |
| --- | --- |
| `endpoint` | HTTPS Proxmox API endpoint. |
| `token_id` | Full management token identifier: `user@realm!token`. |
| `token_secret` | Management token secret; write-only and omitted from reads. |
| `ca_cert` | Optional PEM CA certificate for the Proxmox endpoint. Supply with `ca_cert=@/path/to/ca.pem`. |
| `timeout` | Request timeout duration; defaults to `30s`. |

TLS certificate verification is required. There is no insecure TLS option.
Before saving configuration, the plugin performs authenticated reads to verify
Proxmox VE 9 and the management token's metadata. The management token must
have privilege separation enabled (`privsep=1`). Configuration reads return
non-secret settings only. The API supports read and write at `config`; there
is no configuration delete operation. Required values must be nonempty, and
unknown input fields are rejected. The endpoint and management user cannot
change while roles, managed resources, or recovery records exist.

## Roles

Roles store the settings for credential issuance. Role writes do not provision
Proxmox resources. Configure the management connection
before creating a role; a role may not target the management token's user.
Role writes check the requested Proxmox role or privileges remotely and verify
the permissions of an existing target user. These authenticated validation
reads require access to the configured Proxmox server.

```sh
bao write proxmox/roles/reader \
  user='reader@pve' \
  pve_role=PVEAuditor \
  acl_path=/vms \
  auto_create_user=false \
  propagate=false \
  ttl=15m \
  max_ttl=1h
bao read proxmox/roles/reader
bao list proxmox/roles
bao delete proxmox/roles/reader
```

| Field | Meaning |
| --- | --- |
| `user` | Full target identity in `user@realm` form, distinct from the management user. |
| `auto_create_user` | Whether issuance may create a missing `@pve` user; defaults to `false`. Existing users require engine ownership. |
| `pve_role` | Proxmox role name; specify exactly one of `pve_role` or `privileges`. |
| `privileges` | Privileges for a managed role, as a comma-delimited string or JSON string array; mutually exclusive with `pve_role`. |
| `acl_path` | Proxmox ACL path for issuance, such as `/vms`. |
| `propagate` | Whether the ACL applies to child paths; defaults to `false`. |
| `ttl` | Optional lease duration; zero or omitted uses mount defaults. |
| `max_ttl` | Optional maximum lease duration; zero or omitted uses mount defaults. |

The API supports read, write, and delete at `roles/<name>`, and list at `roles`.
Role reads contain configuration only.

## Management credential rotation

The configured management token must be dedicated to this engine mount.
Rotate it through the standard write endpoint:

```sh
bao write -f proxmox/config/rotate-root
```

The replacement uses `privsep=1`, the same token ACL bindings and propagation,
and the predecessor's expiry. The engine verifies authentication and ACL scope
before storing the replacement privately in seal-wrapped configuration. It
then deletes the predecessor and its token ACLs. Responses contain the current
token ID only; the replacement secret is never returned.

Recovery records contain token identities without credential values. Before a
configuration switch, recovery removes the uncommitted replacement. After the
switch, recovery retires the predecessor. Failed retirement retains the
verified replacement and its recovery record. Repeating the rotation write or
the SDK rollback callback completes recovery; configuration writes are blocked
while recovery is pending. These behaviors have local fixture coverage, with
live PVE acceptance pending.

## Dynamic credentials

Read `proxmox/creds/reader` using an authenticated OpenBao client. The response
contains `token_id`, `token_id_full`, and the newly issued `secret`, together
with a renewable OpenBao lease. Protect the response as a credential. The
engine's management secret is never included in configuration reads or
issued-credential responses.

Each issuance creates a unique token with `privsep=1`, a unique Proxmox role
containing the requested privilege snapshot, and a token ACL at `acl_path`.
The token's effective rights remain bounded by its user's rights. For an
existing user, issuance rechecks the permission ceiling and leaves that user's
permissions unchanged. With `auto_create_user=true`, the engine creates a
passwordless `@pve` user and grants the permission ceiling for its managed
tokens. It refuses to adopt an existing user without an ownership record.

Every issuance and renewal sets an explicit Proxmox expiry deadline. The
returned lease duration uses the remaining whole seconds. Renewal honors the
original maximum lifetime and mount
limits, and verifies privilege separation, expiry, and ACLs. Later changes to
the OpenBao role or named Proxmox role do not broaden an existing token.
Deleting an OpenBao role does not prevent its outstanding leases from being
revoked or renewed within their original limits.

Use OpenBao's normal lease operations with the returned lease ID:

```sh
bao lease renew -increment=15m "$LEASE_ID"
bao lease revoke "$LEASE_ID"
```

Revocation deletes the token, its ACL, and its owned Proxmox role. An owned
user is removed after no configured role or managed token needs it and no
other API tokens remain. Pre-existing users are retained. Unconfirmed remote
deletion is an error so OpenBao can retry. Provisioning uses the SDK's
write-ahead log; retained ownership records allow the backend's periodic
callback to recover expired tokens after restart or failed lease registration.
These recovery records contain identities and deadlines, without token values.

## Static credentials

Static roles manage long-lived, privilege-separated tokens on an interval.
They use the same permission fields as dynamic roles and require a
`rotation_period` between one minute and 365 days. They reject `ttl` and
`max_ttl`, which apply to dynamic leases. Writing a static role provisions a
replacement immediately, including when changing its interval or permissions.

```sh
bao write proxmox/static-roles/reader \
  user='reader@pve' \
  pve_role=PVEAuditor \
  acl_path=/vms \
  propagate=false \
  rotation_period=24h
bao read proxmox/static-roles/reader
bao list proxmox/static-roles
bao read proxmox/static-creds/reader
bao delete proxmox/static-roles/reader
```

`static-creds/<name>` returns the current `token_id`, `token_id_full`, and
`secret`, with `rotation_period`, `last_rotation`, `next_rotation`, and `ttl`.
Repeated reads return the same credential until rotation. There is no OpenBao
lease. The response's `ttl` counts down to scheduled rotation; it is not a
Proxmox expiration deadline. Static tokens have no Proxmox expiry, so rotation
requires the engine to run and reach the Proxmox API.

The engine verifies the replacement's privilege separation and ACL before
committing its secret, role settings, and next rotation time together in
seal-wrapped storage. It then retires the previous token, its ACLs, and its
owned role. The native periodic callback rotates due roles and retries pending
recovery. Stored schedules survive restart. A failed retirement preserves the
committed replacement for authorized reads.

Write-ahead recovery records contain identities without secrets. Recovery
removes an uncommitted replacement or retires a predecessor after commit.
Deleting a static role records a durable deletion intent, removes the readable
credential, and cleans up its owned resources. Recovery retries incomplete
deletion after restart. Dynamic expiry cleanup skips static tokens. Each mount
keeps its own static credentials and schedule.

## Design references and license

The engine follows the official OpenBao
[plugin development guide](https://openbao.org/docs/plugins/plugin-development/)
and its `ServeMultiplex` entrypoint. The official
[AWS](https://github.com/openbao/openbao-plugins/tree/main/secrets/aws) and
[Nomad](https://github.com/openbao/openbao-plugins/tree/main/secrets/nomad)
engines are source references for native leased secrets and revocation.

Original project code is licensed under [Apache License 2.0](LICENSE).
Any copied upstream code must retain its applicable license and notices.
