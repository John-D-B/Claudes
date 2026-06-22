# EJBCA-CE build and test

*Local EJBCA Community Edition stack + workflow scripts.*

**Author:** JohnB, with AI pair-programming support by Anthropic Claude<br/>
**Date:** 2026-06-21

This is a small Docker Compose stack for EJBCA-CE, plus the shell scripts that<br/>
&nbsp; &nbsp; build it from scratch, rebuild it after local source changes, stand up a k3d<br/>
&nbsp; &nbsp; cluster for the cert-manager demo, probe it, and verify two<br/>
&nbsp; &nbsp; community-edition PRs (`Fix-26` REST `DELETE` endpoint and `Fix-27`<br/>
&nbsp; &nbsp; DBMS Maintenance Worker — see [Status](#status) below).

The stack runs on a single machine via `docker compose`. The workflow scripts<br/>
&nbsp; &nbsp; cover the operational arc from *"I just cloned this"* to *"my PR passes its<br/>
&nbsp; &nbsp; integration test"* — each step is idempotent and rerunnable, and each<br/>
&nbsp; &nbsp; script echoes its `curl` / `docker` / `keytool` commands before running them<br/>
&nbsp; &nbsp; so you can copy-paste any individual probe to iterate by hand.

These scripts are the *published* mirror of the live working set used during<br/>
&nbsp; &nbsp; PR-work on `ejbca-ce/9.3.7` — they're the same scripts that produced the<br/>
&nbsp; &nbsp; *"13/13 PASS"* and *"174-cert BYOC"* numbers cited in the PR descriptions.

**New here?**<br/>
I provide two equivalent demo workflows, both automated and manual, with full transparency:
- Scripted fast path: &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; [`DEMO-automated.md`](./DEMO-automated.md)
- Step-by-step run book: &nbsp; &nbsp; [`DEMO-manually.md`](./DEMO-manually.md)

This README is the reference both draw on.

<br/>

## What you get

### Top level of `ejbca-ce/`:

| Path | What |
|---|---|
| `Bin/elt/` | Non-secret config templates:<br/>&nbsp; &nbsp; `- ce-target.env.example`<br/>&nbsp; &nbsp; `- ee-target.env.example`<br/>FYI: *generated* `*-target.env` files are written to `$localDir` |
| `DEMO-automated.md` | Scripted clone-to-verified walkthrough. |
| `DEMO-manually.md` | Step-by-step run book — every command shown. |
| `Docs/` | Supporting documents for the PRs:<br/>&nbsp; &nbsp; - Fix-27 and Fix-26 design docs<br/>&nbsp; &nbsp; - Fix-27 and Fix-26 test plans<br/>&nbsp; &nbsp; - admin-GUI mockup: `fix27-gui-mockup.png`<br/>&nbsp; &nbsp; - CE REST End-Entity gap analysis: why ELT speaks SOAP to CE |
| `README-ejbca-ce.md` | This file. |
| `images/` | Screenshots referenced by `DEMO-manually.md`. |
| `patches/` | The `Fix-26` / `Fix-27` source patches,<br/>&nbsp; &nbsp; applied by `231.build-local-image.sh`. |
| `references/` | Historical logs of JohnB's manual workflow,<br/>&nbsp; &nbsp; for comparison with your own work. |
| `requirements.txt` | Python deps for the bundled tools:<br/>&nbsp; &nbsp;  - `zeep` for ELT's SOAP backend<br/>&nbsp; &nbsp; - `cryptography` for **cert-grep** |
| `stack/` | Docker container stacks:<br/>&nbsp; &nbsp; - `mariadb` (database, state)<br/>&nbsp; &nbsp; - `ejbca-ce` (web app server) |


### Workflow script groups:

| Script group | Purpose | When you run it |
|---|---|---|
| `Bin/200.build/` | From-scratch server build —<br/>&nbsp; &nbsp; orchestrator that drives `210.bootstrap/` | Once, after `git clone` |
| `Bin/210.bootstrap/` | Stack bring-up + admin bootstrap + profile import | Via `201`, or step-by-step |
| `Bin/220.certs/` | Export the server cert to `$certsDir`,<br/>&nbsp; &nbsp; and write `$localDir/ce-target.env`<br/>&nbsp; &nbsp; (`214` wrote the client cert + CA) | After bootstrap |
| `Bin/230.rebuild/` | Rebuild the EJBCA container with local source edits | Every time the EJBCA Java code changes |
| `Bin/300.cluster/` | Stand up the k3d cluster + CoreDNS<br/>&nbsp; &nbsp; for the cert-manager demo | Before the K8s cert-manager demo |
| `Bin/500.verify-PR/` | Integration tests that lock in PR-fix behaviour | After rebuilds that touches PR-relevant code |
| `Bin/900.probes/` | Ad-hoc protocol probes (SOAP / REST / smoke) | When you want a quick health/protocol check |

Scripts inside each group are numbered from `decade+1` and run in sort order<br/>
&nbsp; &nbsp; (e.g. `211 → 212 → 213 → …` inside `Bin/210.bootstrap/`). The hundreds<br/>
&nbsp; &nbsp; digit groups them by workflow phase (`2xx` = server, `3xx` =<br/>
&nbsp; &nbsp; cluster, `5xx` = PR verification, `9xx` = probes) and aligns with the<br/>
&nbsp; &nbsp; sections of the [`DEMO-manually.md`](./DEMO-manually.md) walkthrough.

**Orchestrator** groups drive others and live outside the glob<br/>
&nbsp; &nbsp; they run: `200.build/201.build-server.sh` runs all of `210.bootstrap/*.sh`<br/>
&nbsp; &nbsp; then `220.certs/221.collect-certs.sh`;<br/>
&nbsp; &nbsp; `300.cluster/301.build-cluster.sh` builds the k3d cluster in one step.

The 3-digit scheme is intentional: it visually distinguishes the convention<br/>
&nbsp; &nbsp; from any legacy `<phase>.<step>` scripts (`1.4d`, `3.5`, etc.) that might<br/>
&nbsp; &nbsp; appear in DEV-only contexts.

<br/>

## Layout (what you should see after cloning)

```
ejbca-ce/
├── Bin/
│   ├── 200.build/
│   │   └── 201.build-server.sh
│   ├── 210.bootstrap/
│   │   ├── 211.verify-stack.sh
│   │   ├── 212.bootstrap-superadmin.sh
│   │   ├── 213.enable-rest-api.sh
│   │   ├── 214.create-admin.sh
│   │   ├── 215.populate-truststore.sh
│   │   ├── 216.verify-mtls.sh
│   │   ├── 217.import-profiles.sh
│   │   ├── 218.verify-profiles.sh
│   │   └── 219.reissue-server-cert.sh
│   ├── 220.certs/
│   │   └── 221.collect-certs.sh
│   ├── 230.rebuild/
│   │   ├── 231.build-local-image.sh
│   │   └── 232.swap-stack-image.sh
│   ├── 300.cluster/
│   │   └── 301.build-cluster.sh
│   ├── 500.verify-PR/
│   │   ├── 501.fix-26-integration-test.sh
│   │   └── 502.fix-27-integration-test.sh
│   ├── 900.probes/
│   │   ├── 901.smoke-test.sh
│   │   ├── 902.probe-soap.sh
│   │   └── 903.inspect-wsdl.sh
│   └── elt/
│       ├── ce-target.env.example
│       └── ee-target.env.example
├── DEMO-automated.md
├── DEMO-manually.md
├── Docs/
│   ├── ejbca-ce-rest-endentity-gap.md
│   ├── ejbca-ce-task-3.4-dbms-worker-design.md
│   ├── ejbca-ce-task-3.5-fix-27-test-plan.md
│   ├── ejbca-ce-task-3.6-rest-delete-design.md
│   ├── ejbca-ce-task-3.7-fix-26-test-plan.md
│   ├── fix27-gui-mockup.png
│   └── fix27-gui-mockup.svg
├── README-ejbca-ce.md
├── images/
│   ├── EJBCA-CE_client_cert.png
│   ├── EJBCA-CE_in_browser.png
│   ├── Firefox-cert-ELT-Admin.png
│   ├── Firefox-cert-ManagementCA.png
│   ├── fix27-gui-mockup-scaled.png
│   └── fix27-gui-mockup.png
├── patches/
│   ├── fix-26.patch
│   └── fix-27.patch
├── references/
│   └── logs.2026-06-22.zip
├── requirements.txt
└── stack/
    ├── Dockerfile.local-fixes
    ├── README-stack.md
    ├── coredns-custom.yaml
    ├── docker-compose.yml
    └── init-release17.gradle.kts
```

The build writes **no credentials inside the clone**. The working certs go to an<br/>
&nbsp; &nbsp; out-of-repo `$certsDir` (default `/tmp/claude/demo/certs/`): `214` writes the<br/>
&nbsp; &nbsp; admin cert + key + CA there, `221` adds the exported server cert; the<br/>
&nbsp; &nbsp; generated `ce-target.env` goes to `$localDir` (default `…/demo/local/`). Both<br/>
&nbsp; &nbsp; are created on first run. See [Credentials supply](#credentials-supply).

<br/>

## Quick start

```bash
# (1) Build the server from scratch: wipe + bring up the stack, wait for
#     readiness, run the 210.bootstrap/ sequence, then collect the certs and
#     write $localDir/ce-target.env (221) — all in one step.
Bin/200.build/201.build-server.sh

# (2) Load the generated connection config (host, ports, client cert/key/CA).
source "${localDir:-/tmp/claude/demo/local}/ce-target.env"

# (3) Probe that REST + SOAP are reachable with mTLS.
Bin/210.bootstrap/216.verify-mtls.sh
Bin/900.probes/902.probe-soap.sh

# (4) Run a smoke test against the stack.
Bin/900.probes/901.smoke-test.sh --target ce
```

To exercise either PR locally:

```bash
# Build a local-fixes image that includes your worktree edits.
Bin/230.rebuild/231.build-local-image.sh
Bin/230.rebuild/232.swap-stack-image.sh ejbca-ce:local-fixes

# Run the PR's integration test.
Bin/500.verify-PR/502.fix-27-integration-test.sh    # Fix-27 (DBMS worker)
Bin/500.verify-PR/501.fix-26-integration-test.sh    # Fix-26 (REST DELETE)
```

For the Kubernetes cert-manager demo, stand up the cluster first:

```bash
Bin/300.cluster/301.build-cluster.sh
```

<br/>

## Local DEV alias

Scripts default to `host.k3d.internal` rather than `localhost` so they work<br/>
&nbsp; &nbsp; uniformly whether the EJBCA stack is at loopback (single-machine DEV)<br/>
&nbsp; &nbsp; or behind a k3d-resolved hostname.

For convenient local DEV, add to `/etc/hosts`:

```
127.0.0.1   host.k3d.internal
```

That makes `host.k3d.internal` resolve to loopback so the same scripts work<br/>
&nbsp; &nbsp; against the local Docker stack and against k3d-routed EJBCA without code<br/>
&nbsp; &nbsp; changes. The EJBCA server cert provisioned by<br/>
&nbsp; &nbsp; `Bin/210.bootstrap/219.reissue-server-cert.sh` includes `host.k3d.internal`<br/>
&nbsp; &nbsp; in its SANs, so TLS verification works against this name out of the box.

<br/>

## HOST= override

Every script that talks to EJBCA accepts a `HOST=` env override:

```bash
HOST=ejbca.example.com Bin/900.probes/901.smoke-test.sh --target ce
```

The default is `host.k3d.internal`. The override is bare-hostname (no scheme,<br/>
&nbsp; &nbsp; no port) — scripts use `http://${HOST}:8080/...` for healthcheck endpoints<br/>
&nbsp; &nbsp; and `https://${HOST}:8443/...` for the admin GUI, REST, and SOAP.

<br/>

## Credentials supply

The build writes the working certs to an out-of-repo `$certsDir` (default<br/>
&nbsp; &nbsp; `/tmp/claude/demo/certs/`) — never inside the clone — plus a generated<br/>
&nbsp; &nbsp; `$localDir/ce-target.env` that ELT and the probe scripts read:

| File (`$certsDir/…`) | What | Written by |
|---|---|---|
| `ELT-Admin.crt` | Admin client cert | `214.create-admin.sh` |
| `ELT-Admin.key` | Admin client key | `214.create-admin.sh` |
| `ELT-Admin.p12` | Admin client P12 | `214.create-admin.sh` |
| `ELT-Admin.password` | P12 password for the above | `214.create-admin.sh` |
| `ManagementCA.crt` | ManagementCA cert (CA bundle for mTLS) | `214.create-admin.sh` |
| `SuperAdmin.{jks,p12,password}` | Auto-bootstrap SuperAdmin keystore:<br/>&nbsp; &nbsp; for admin work needing SuperAdmin,<br/>&nbsp; &nbsp; rather than ELT-Admin.| `212.bootstrap-superadmin.sh` |
| `host.k3d.internal.crt` | EJBCA's server TLS cert (exported leaf) | `221.collect-certs.sh` |

`214` writes the client cert + key + CA straight into `$certsDir` (no in-repo<br/>
&nbsp; &nbsp; staging); `221` adds the server cert (exported from the container keystore)<br/>
&nbsp; &nbsp; and writes `ce-target.env`. Once the build has run, the credentials are<br/>
&nbsp; &nbsp; reusable across reboots and restarts — they live in `$certsDir` on the host,<br/>
&nbsp; &nbsp; not inside the EJBCA container and not inside the cloned repo.

<br/>

## What each script group does, in more detail

### `Bin/200.build/` — from-scratch server build

`201.build-server.sh` — orchestrator. Resets the compose image to the upstream<br/>
&nbsp; &nbsp; base, wipes and brings up the Compose stack (`docker compose down -v` then<br/>
&nbsp; &nbsp; `up -d`), waits for the admin GUI to answer `200`, runs every<br/>
&nbsp; &nbsp; `Bin/210.bootstrap/*.sh` in order, then collects the certs via<br/>
&nbsp; &nbsp; `220.certs/221.collect-certs.sh`. One command to go from a clean clone to a<br/>
&nbsp; &nbsp; bootstrapped server with `$localDir/ce-target.env` ready to source — a fresh<br/>
&nbsp; &nbsp; bootstrap mints a new ManagementCA, so collecting in the same run is what<br/>
&nbsp; &nbsp; keeps the certs valid.

### `Bin/210.bootstrap/` — stack bring-up + admin bootstrap

`211.verify-stack.sh` — confirm both containers are up, MariaDB has its schema,<br/>
&nbsp; &nbsp; and the HTTPS admin GUI answers `200` (the reliable app-ready signal).

`212.bootstrap-superadmin.sh` — refresh the auto-bootstrapped SuperAdmin EE and<br/>
&nbsp; &nbsp; export its keystore to `$certsDir` as `SuperAdmin.{jks,p12,password}` for<br/>
&nbsp; &nbsp; admin work needing SuperAdmin. Day-to-day admin uses `214`'s `ELT-Admin`.

`213.enable-rest-api.sh` — turn on EJBCA's REST protocols via System<br/>
&nbsp; &nbsp; Configuration.

`214.create-admin.sh` — create a distinct admin End Entity (`ELT-Admin` by<br/>
&nbsp; &nbsp; default) with REST role membership, enrol it, and produce the resulting<br/>
&nbsp; &nbsp; cert + key + P12.

`215.populate-truststore.sh` — import ManagementCA into WildFly's truststore<br/>
&nbsp; &nbsp; so mTLS handshakes verify.

`216.verify-mtls.sh` — confirm mTLS REST access works against representative<br/>
&nbsp; &nbsp; endpoints. This script is the **reference pattern** for the project's<br/>
&nbsp; &nbsp; *"echo the curl command before running it"* convention.

`217.import-profiles.sh` — import the End Entity Profile and Certificate Profile<br/>
&nbsp; &nbsp; the demo relies on, re-binding them to the running ManagementCA (whose<br/>
&nbsp; &nbsp; `caid` is randomised per fresh install).

`218.verify-profiles.sh` — confirm those profiles are visible to ELT via SOAP.

`219.reissue-server-cert.sh` — re-issue EJBCA's WildFly server TLS cert with<br/>
&nbsp; &nbsp; reachable SANs (`host.k3d.internal`, `localhost`, `host.docker.internal`,<br/>
&nbsp; &nbsp; container hostname). Required for in-cluster cert-manager Issuer<br/>
&nbsp; &nbsp; verification.

### `Bin/220.certs/` — collect credentials

`221.collect-certs.sh` — export the server TLS cert (the leaf, via `keytool`)<br/>
&nbsp; &nbsp; from the running stack into `$certsDir`, and write the generated<br/>
&nbsp; &nbsp; `$localDir/ce-target.env` consumed by ELT and the probe scripts. (`214` already<br/>
&nbsp; &nbsp; wrote the admin cert + key + P12 + ManagementCA into `$certsDir`.)

### `Bin/230.rebuild/` — rebuild after a code edit

`231.build-local-image.sh` — full pipeline: gradle build (produces a fresh EAR),<br/>
&nbsp; &nbsp; then `docker build` wrapping the EAR onto the upstream CE base image,<br/>
&nbsp; &nbsp; producing `ejbca-ce:local-fixes`. Supports `--skip-ear` to reuse the<br/>
&nbsp; &nbsp; last EAR (docker step only).

`232.swap-stack-image.sh` — swap the EJBCA container's image and recreate it.<br/>
&nbsp; &nbsp; Pass the image tag (`ejbca-ce:local-fixes` or `keyfactor/ejbca-ce:latest`<br/>
&nbsp; &nbsp; to revert).

### `Bin/300.cluster/` — k3d cluster for the cert-manager demo

`301.build-cluster.sh` — create the `ejbca-test` k3d cluster, apply<br/>
&nbsp; &nbsp; `stack/coredns-custom.yaml`, and restart CoreDNS so `host.k3d.internal`<br/>
&nbsp; &nbsp; resolves to the host from inside the cluster — the prerequisite for the<br/>
&nbsp; &nbsp; in-cluster cert-manager Issuer to reach the EJBCA backend.

### `Bin/500.verify-PR/` — PR-fix integration tests

`501.fix-26-integration-test.sh` — exercises the new<br/>
&nbsp; &nbsp; `DELETE /v1/certificate/{issuer_dn}/{serial}` REST endpoint added by<br/>
&nbsp; &nbsp; **PR-fix-26**. Self-prov mode (T1–T9) provisions its own fixtures; BYOC<br/>
&nbsp; &nbsp; mode (`--ee-username + --elt + --reaper-ok`) iterates over existing<br/>
&nbsp; &nbsp; revoked certs from a real-world inventory.

`502.fix-27-integration-test.sh` — exercises the new DBMS Maintenance Worker<br/>
&nbsp; &nbsp; (`MODE_REVOKED`) added by **PR-fix-27**. Provisions 13 test fixtures<br/>
&nbsp; &nbsp; spanning the E/R/r lifecycle states including the `status=60` ARCHIVED<br/>
&nbsp; &nbsp; substate, runs the worker on a 1-minute interval, and asserts the<br/>
&nbsp; &nbsp; expected sweep + survivorship pattern (T1–T13).

### `Bin/900.probes/` — ad-hoc protocol checks

`901.smoke-test.sh` — automated smoke runner. Targets `ce` (default) or `ee`<br/>
&nbsp; &nbsp; (community vs enterprise — for EE, sources `Bin/elt/ee-target.env`).

`902.probe-soap.sh` — confirm the EJBCA SOAP Web Service is reachable via mTLS<br/>
&nbsp; &nbsp; and the WSDL parses.

`903.inspect-wsdl.sh` — catalogue the SOAP End Entity operations exposed by<br/>
&nbsp; &nbsp; this EJBCA version — useful when ELT's SOAP backend needs to map a new<br/>
&nbsp; &nbsp; operation.

<br/>

## Status

These scripts are the working set behind two Community Edition pull requests<br/>
&nbsp; &nbsp; from the same single-developer + Claude pair-programming workflow that<br/>
&nbsp; &nbsp; produced [`Keyfactor/ejbca-cert-manager-issuer` PR #129](https://github.com/Keyfactor/ejbca-cert-manager-issuer/pull/129):

- **Fix-27 — DBMS Maintenance Worker** (`MODE_REVOKED` cleanup mode):<br/>
&nbsp; &nbsp; verified via `Bin/500.verify-PR/502.fix-27-integration-test.sh`<br/>
&nbsp; &nbsp; (13/13 PASS).
- **Fix-26 — REST `DELETE /v1/certificate/{issuer_dn}/{serial}`** endpoint:<br/>
&nbsp; &nbsp; verified via `Bin/500.verify-PR/501.fix-26-integration-test.sh`<br/>
&nbsp; &nbsp; (174-cert BYOC + T1–T9 self-prov).

This dated directory (`2026-06-01.EJBCA-tools/`) is maintained in place until<br/>
&nbsp; &nbsp; superseded by a later dated directory; inbound links stay stable either way.

Issues, suggestions, and contributions are welcome via the parent<br/>
&nbsp; &nbsp; [`John-D-B/Claudes`](https://github.com/John-D-B/Claudes) repo.
