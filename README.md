---
type: project
title: OpenBao Proxmox secrets engine
description: Gate 1 foundation for an OpenBao external secrets engine for Proxmox VE.
tags: [openbao, proxmox, foundation]
timestamp: 2026-10-03T16:52:45Z
---

This project is at **Gate 1: foundation only**. It provides a multiplexed
OpenBao plugin, validated connection configuration, and role storage. It
**cannot issue credentials yet**. Writing a role does not create a Proxmox
user, role, ACL, or API token. Dynamic credentials, lease revocation, management
token replacement, and static-role rotation are planned work.

See the [implementation plan](docs/implementation-plan.md) for phase boundaries
and acceptance gates. Proxmox VE 9 live acceptance and a release candidate are
later gates; this foundation is not a production release.

## Build and test

Enter the repository's development shell, then use the standard Go commands:

```sh
nix develop
go build ./cmd/openbao-plugin-secrets-proxmox
go test -race ./...
BAO_TEST_BINARY=bao go test -race -run TestOpenBaoMounts -v .
```

The dependency baseline is Go 1.27, OpenBao SDK/API v2.7.1, and
`github.com/luthermonson/go-proxmox` v0.8.2. The tests exercise the foundation;
they do not establish live Proxmox credential lifecycle support. The opt-in
OpenBao test builds and registers the plugin in an isolated, loopback-only
development server. It checks two configured mounts against TLS PVE fixtures,
including continued operation after unmounting one instance.

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
change while roles exist.

## Roles

Roles store the settings intended for future credential issuance. They do not
provision anything in Proxmox at this phase. Configure the management connection
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
| `auto_create_user` | Whether future issuance may create a missing target user; defaults to `false`. |
| `pve_role` | Proxmox role name; specify exactly one of `pve_role` or `privileges`. |
| `privileges` | Privileges for a future managed role, as a comma-delimited string or JSON string array; mutually exclusive with `pve_role`. |
| `acl_path` | Proxmox ACL path for future issuance, such as `/vms`. |
| `propagate` | Whether the future ACL applies to child paths; defaults to `false`. |
| `ttl` | Optional lease duration for future credentials; zero or omitted uses mount defaults. |
| `max_ttl` | Optional maximum lease duration for future credentials; zero or omitted uses mount defaults. |

The API supports read, write, and delete at `roles/<name>`, and list at `roles`.
Role reads contain configuration only. No `creds/<name>`, root rotation, or
static-role endpoints are implemented at Gate 1.

## Design references and license

The foundation follows the official OpenBao
[plugin development guide](https://openbao.org/docs/plugins/plugin-development/)
and its `ServeMultiplex` entrypoint. The official
[AWS](https://github.com/openbao/openbao-plugins/tree/main/secrets/aws) and
[Nomad](https://github.com/openbao/openbao-plugins/tree/main/secrets/nomad)
engines are source references for subsequent lifecycle work, not evidence
that those features exist here.

Original project code is licensed under [Apache License 2.0](LICENSE).
Any copied upstream code must retain its applicable license and notices.
