---
type: implementation-plan
title: Proxmox secrets engine implementation gates
description: Phased implementation and acceptance criteria for a Proxmox OpenBao secrets engine.
tags: [openbao, proxmox, plan]
timestamp: 2026-10-04T13:50:00Z
---

The approved implementation scope is **Gate 3**. Dynamic credentials are
implemented with local fixture coverage; live PVE 9 acceptance is pending.
An explicit gate exception authorizes rotation implementation while deferring
live acceptance. It does not accept Gate 2 or authorize production deployment.
The [README](../README.md) is the current configuration and role reference.

## Phases

| Phase | Scope | Availability |
| --- | --- | --- |
| 1 | Multiplexed plugin; secure connection configuration; validated role read, write, delete, and list; build and tests. | Implemented and locally verified. |
| 2 | Leased `privsep=1` tokens; provisioning at issuance; native `framework.Secret` revocation. | Implemented; live acceptance pending. |
| 3 | Private management token replacement; static roles and rotation. | Rotation implemented and tested locally; live acceptance deferred. |
| 4 | PVE and OpenBao acceptance; signed artifacts and operational documentation. | Planned; no production publication. |

Phase 2 uses a unique managed Proxmox role per token to preserve the requested
privilege snapshot. Issuance grants the token's ACL, records its immutable
identity, and returns a native leased secret. Renewal preserves the original
maximum lifetime. Revocation works independently of later role changes or
deletion. SDK write-ahead logging and retained ownership records cover partial
provisioning, cleanup retries, and the lease-registration boundary. Recovery
state contains no credential values. Optional user provisioning creates only
owned passwordless `@pve` users and cleans them after all dependencies end.

## Acceptance gates

Each gate requires captured, reproducible evidence. A source build or unit test
does not establish live server behavior.

1. **Gate 1: Foundation.** Build the plugin and run race tests. Register and
   exercise two local OpenBao mounts. Prove configuration and role validation,
   secret omission, and mount isolation. Stop before implementing issuance.
2. **Gate 2: Dynamic lifecycle.** Issue a leased privilege-separated token on
   non-production Proxmox VE 9 and OpenBao. Prove permitted and denied actions.
   Prove explicit revoke and lease expiry delete the token. Exercise cleanup
   failure and retry. Establish lifecycle behavior through API observations.
3. **Gate 3: Rotation and recovery.** Prove management-token replacement keeps
   a working replacement privately and retires the old token. Prove static
   rotation, restart recovery, and failure handling without secret disclosure.
   Establish this behavior through live observations.
4. **Gate 4: Release candidate.** Review the complete change in a PR. Pass the
   PVE 9 acceptance matrix. Verify signed release-candidate artifacts and
   matching public/private documentation. Stop before production publication.

Record each scenario's invocation, pass/fail observable, and artifact location.
Live acceptance must identify the tested versions and distinguish local tests
from actual token creation and deletion. Keep operational identities, access
procedures, and secret values out of public documentation and evidence.

## Remaining work

Gate 2 still requires live PVE 9 evidence to establish allowed and denied
actions and actual token deletion. A local API fixture does not replace this
gate. The Gate 3 implementation exception permits code and local testing;
live acceptance and production deployment remain separate decisions.

At Gate 3, add `config/rotate-root`, `static-roles/<name>`, and
`static-creds/<name>` using the existing SDK callbacks and storage. Management
token replacement must create and verify the replacement before retiring the
old token, persist recovery state across interruptions, and return no private
credential. Static rotation must retain a usable token until its replacement
is verified, resume after restart, and follow each role's rotation schedule.

Implement management rotation before static rotation. Preserve the configured
management token's own ACL scope on a privilege-separated replacement. Persist
the verified replacement only in seal-wrapped credential storage. Recovery
records carry identities and lifecycle state, never credential values. Test
interruption before and after the credential switch, rejected storage writes,
failed retirement, restart recovery, and cross-mount isolation.

Static rotation must preserve each role's declared permission scope and keep
the current credential available until replacement is verified and stored.
Test scheduled replacement, failed replacement and retirement, restart with a
pending rotation, role deletion, and management-user exclusion. Reuse the SDK
periodic callback, durable storage, and WAL rather than adding a scheduler
service. Gate 4 remains pending until real PVE acceptance and release-artifact
verification are complete.

## Native interfaces and references

Use the OpenBao SDK's existing plugin and secret lifecycle interfaces. The
[plugin development guide](https://openbao.org/docs/plugins/plugin-development/)
documents the multiplexed entrypoint. The maintained
[AWS secrets engine](https://github.com/openbao/openbao-plugins/tree/main/secrets/aws)
and [Nomad secrets engine](https://github.com/openbao/openbao-plugins/tree/main/secrets/nomad)
provide upstream source references for leased credentials and revocation.

The dependency baseline for the foundation is Go 1.27, OpenBao SDK and API
v2.7.1, and `go-proxmox` v0.8.2. Preserve the Apache 2.0 license for original
project code and retain upstream notices wherever upstream code is copied.
