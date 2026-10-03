---
type: implementation-plan
title: Proxmox secrets engine implementation gates
description: Phased implementation and acceptance criteria for a Proxmox OpenBao secrets engine.
tags: [openbao, proxmox, plan]
timestamp: 2026-10-03T16:52:45Z
---

The current scope ends at **Gate 1**. The foundation cannot issue credentials.
The following phases describe planned capabilities, not available API promises.
The [README](../README.md) is the current configuration and role reference.

## Phases

| Phase | Scope | Availability |
| --- | --- | --- |
| 1 | Multiplexed plugin; secure connection configuration; validated role read, write, delete, and list; build and tests. | Current foundation scope. |
| 2 | Leased `privsep=1` tokens; provisioning at issuance; native `framework.Secret` revocation. | Planned. |
| 3 | Private management token replacement; static roles and rotation. | Planned. |
| 4 | PVE and OpenBao acceptance; signed artifacts and operational documentation. | Planned; no production publication. |

Phase 2 will define the exact privilege provisioning, lease renewal, cleanup,
and failure-recovery behavior before exposing issuance. Role settings such as
`auto_create_user`, ACL propagation, and lease durations are stored in Phase 1
for that future behavior. Phase 1 creates no Proxmox resources.

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
