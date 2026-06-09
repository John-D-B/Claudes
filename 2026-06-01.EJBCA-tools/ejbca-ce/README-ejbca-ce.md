# `ejbca-ce/` — local EJBCA Community Edition stack + workflow scripts

**Author:** JohnB, with AI pair-programming support by Anthropic Claude<br/>
**Date:** 2026-06-05

A small Docker Compose stack for EJBCA-CE, plus the shell scripts that bring it<br/>
&nbsp; &nbsp; up, rebuild it after local source changes, probe it, and verify two<br/>
&nbsp; &nbsp; community-edition PRs (`Fix-26` REST `DELETE` endpoint and `Fix-27`<br/>
&nbsp; &nbsp; DBMS Maintenance Worker — see [Status](#status) below).

The stack runs on a single machine via `docker compose`. The workflow scripts<br/>
&nbsp; &nbsp; cover the operational arc from *"I just cloned this"* to *"my PR passes its<br/>
&nbsp; &nbsp; integration test"* — each step is idempotent and rerunnable, and each<br/>
&nbsp; &nbsp; script echoes its `curl`/`docker`/`openssl` commands before running them so<br/>
&nbsp; &nbsp; you can copy-paste any individual probe to iterate by hand.

These scripts are the *published* mirror of the live working set used during<br/>
&nbsp; &nbsp; PR-work on `ejbca-ce/9.3.7` — they're the same scripts that produced the<br/>
&nbsp; &nbsp; *"13/13 PASS"* and *"174-cert BYOC"* numbers cited in the PR descriptions.

<br/>

## What you get

Four bucketed workflow phases, each its own `Bin/<NNN>.<purpose>/` sub-dir:

| Bucket | Purpose | When you run it |
|---|---|---|
| `Bin/100.setup/` | Stack bring-up + admin bootstrap | Once, after `git clone` |
| `Bin/120.rebuild/` | Rebuild the EJBCA container with your local source edits | Every time you change EJBCA Java code |
| `Bin/130.probes/` | Ad-hoc protocol probes (SOAP / REST / smoke) | Whenever you want a quick health/protocol check |
| `Bin/140.verify-PR/` | Integration tests that lock in PR-fix behaviour | After every rebuild that touches PR-relevant code |

Scripts inside each bucket are numbered from `decade+1` and run in sort order<br/>
&nbsp; &nbsp; (e.g. `101 → 102 → 103 → …` inside `Bin/100.setup/`). The 3-digit scheme<br/>
&nbsp; &nbsp; is intentional: it visually distinguishes the new convention from any<br/>
&nbsp; &nbsp; legacy `<phase>.<step>` scripts (`1.4d`, `3.5`, etc.) that might appear<br/>
&nbsp; &nbsp; in DEV-only contexts.

Also at the top of `ejbca-ce/`:

| Path | What |
|---|---|
| `stack/docker-compose.yml` | Two-container stack — `mariadb` (state) + `ejbca` (the CE server). |
| `stack/Dockerfile.local-fixes` | Build wrapper that ships your local-source EJBCA EAR into the upstream CE base image. Used by `Bin/120.rebuild/121.build-local-image.sh`. |
| `README-ejbca-ce.md` | This file. |

<br/>

## Layout (what you should see after cloning)

```
ejbca-ce/
├── README-ejbca-ce.md
├── stack/
│   ├── docker-compose.yml
│   └── Dockerfile.local-fixes
└── Bin/
    ├── 100.setup/
    │   ├── 101.verify-stack.sh
    │   ├── 102.bootstrap-superadmin.sh
    │   ├── 103.enable-rest-api.sh
    │   ├── 104.create-admin.sh
    │   ├── 105.populate-truststore.sh
    │   ├── 106.verify-mtls.sh
    │   ├── 107.reissue-server-cert.sh
    │   └── 108.verify-profiles.sh
    ├── 120.rebuild/
    │   ├── 121.build-local-image.sh
    │   └── 122.swap-stack-image.sh
    ├── 130.probes/
    │   ├── 131.smoke-test.sh
    │   ├── 132.probe-soap.sh
    │   └── 133.inspect-wsdl.sh
    └── 140.verify-PR/
        ├── 141.fix-26-integration-test.sh
        └── 142.fix-27-integration-test.sh
```

You will also create `ejbca-ce/Creds/elt/` at runtime — the scripts in<br/>
&nbsp; &nbsp; `Bin/100.setup/` and `Bin/130.probes/` write the admin cert + key + CA<br/>
&nbsp; &nbsp; bundle there. The directory is git-ignored (the scripts will create it<br/>
&nbsp; &nbsp; on first run if missing). See [Credentials supply](#credentials-supply).

<br/>

## Quick start

```bash
# (1) Bring up the stack with the upstream community-edition image.
cd ejbca-ce/stack && docker compose up -d && cd -

# (2) Run the setup bucket in order. Each script is idempotent.
for s in Bin/100.setup/*.sh; do "$s" || break; done

# (3) Probe that REST + SOAP are reachable with mTLS.
Bin/100.setup/106.verify-mtls.sh
Bin/130.probes/132.probe-soap.sh

# (4) Run a smoke test against the stack.
Bin/130.probes/131.smoke-test.sh --target ce
```

To exercise either PR locally:

```bash
# Build a local-fixes image that includes your worktree edits.
Bin/120.rebuild/121.build-local-image.sh
Bin/120.rebuild/122.swap-stack-image.sh ejbca-ce:local-fixes

# Run the PR's integration test.
Bin/140.verify-PR/142.fix-27-integration-test.sh    # Fix-27 (DBMS worker)
Bin/140.verify-PR/141.fix-26-integration-test.sh    # Fix-26 (REST DELETE)
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
&nbsp; &nbsp; changes. The EJBCA server cert provisioned by `Bin/100.setup/107.reissue<br/>
&nbsp; &nbsp; -server-cert.sh` includes `host.k3d.internal` in its SANs, so TLS<br/>
&nbsp; &nbsp; verification works against this name out of the box.

<br/>

## HOST= override

Every script that talks to EJBCA accepts a `HOST=` env override:

```bash
HOST=ejbca.example.com Bin/130.probes/131.smoke-test.sh --target ce
```

The default is `host.k3d.internal`. The override is bare-hostname (no scheme,<br/>
&nbsp; &nbsp; no port) — scripts use `http://${HOST}:8080/...` for healthcheck endpoints<br/>
&nbsp; &nbsp; and `https://${HOST}:8443/...` for the admin GUI, REST, and SOAP.

<br/>

## Credentials supply

The scripts in `Bin/100.setup/` produce a credential set under<br/>
&nbsp; &nbsp; `ejbca-ce/Creds/elt/` that downstream buckets reuse:

| File | What | Produced by |
|---|---|---|
| `ce-eltadmin.crt` | Admin client cert | `104.create-admin.sh` |
| `ce-eltadmin.key` | Admin client key | `104.create-admin.sh` |
| `ce-eltadmin.password` | P12 password for the above | `104.create-admin.sh` |
| `ce-managementca.crt` | ManagementCA certificate (CA bundle for mTLS) | `105.populate-truststore.sh` |
| `ce-server-mtls.*` | EJBCA's server TLS cert + key + JKS + P12 + password | `107.reissue-server-cert.sh` |

Once `Bin/100.setup/` has run cleanly, the credentials are reusable across<br/>
&nbsp; &nbsp; reboots, rebuilds, and stack restarts — they live on the host filesystem<br/>
&nbsp; &nbsp; under `ejbca-ce/Creds/elt/`, not inside the EJBCA container.

<br/>

## What each bucket does, in more detail

### `Bin/100.setup/` — stack bring-up + admin bootstrap

`101.verify-stack.sh` — confirm both containers are up, MariaDB has its schema,<br/>
&nbsp; &nbsp; HTTP healthcheck returns ALLOK, HTTPS admin GUI handshake succeeds.

`102.bootstrap-superadmin.sh` — re-issue the auto-bootstrapped SuperAdmin so<br/>
&nbsp; &nbsp; the bootstrap-only cert is replaced by a long-lived admin cert.

`103.enable-rest-api.sh` — turn on EJBCA's REST protocols via System<br/>
&nbsp; &nbsp; Configuration.

`104.create-admin.sh` — create a distinct admin End Entity (`ELT-Admin` by<br/>
&nbsp; &nbsp; default) with REST role membership, enrol it, and write the resulting<br/>
&nbsp; &nbsp; cert + key + P12 to `Creds/elt/`.

`105.populate-truststore.sh` — import ManagementCA into WildFly's truststore<br/>
&nbsp; &nbsp; so mTLS handshakes verify.

`106.verify-mtls.sh` — confirm mTLS REST access works against representative<br/>
&nbsp; &nbsp; endpoints. This script is the **reference pattern** for the project's<br/>
&nbsp; &nbsp; *"echo the curl command before running it"* convention.

`107.reissue-server-cert.sh` — re-issue EJBCA's WildFly server TLS cert with<br/>
&nbsp; &nbsp; reachable SANs (`host.k3d.internal`, `localhost`, `host.docker.internal`,<br/>
&nbsp; &nbsp; container hostname). Required for in-cluster cert-manager Issuer<br/>
&nbsp; &nbsp; verification.

`108.verify-profiles.sh` — confirm the End Entity Profile and Certificate<br/>
&nbsp; &nbsp; Profile created in the admin GUI are visible to ELT via SOAP.

### `Bin/120.rebuild/` — rebuild after a code edit

`121.build-local-image.sh` — full pipeline: gradle build (produces a fresh EAR),<br/>
&nbsp; &nbsp; then `docker build` wrapping the EAR onto the upstream CE base image,<br/>
&nbsp; &nbsp; producing `ejbca-ce:local-fixes`. Supports `--skip-ear` to reuse the<br/>
&nbsp; &nbsp; last EAR (docker step only).

`122.swap-stack-image.sh` — swap the EJBCA container's image and recreate it.<br/>
&nbsp; &nbsp; Pass the image tag (`ejbca-ce:local-fixes` or `keyfactor/ejbca-ce:latest`<br/>
&nbsp; &nbsp; to revert).

### `Bin/130.probes/` — ad-hoc protocol checks

`131.smoke-test.sh` — automated smoke runner. Targets `ce` (default) or `ee`<br/>
&nbsp; &nbsp; (community vs enterprise — for EE, sources `Bin/elt/ee-target.env`).

`132.probe-soap.sh` — confirm the EJBCA SOAP Web Service is reachable via mTLS<br/>
&nbsp; &nbsp; and the WSDL parses.

`133.inspect-wsdl.sh` — catalogue the SOAP End Entity operations exposed by<br/>
&nbsp; &nbsp; this EJBCA version — useful when ELT's SOAP backend needs to map a new<br/>
&nbsp; &nbsp; operation.

### `Bin/140.verify-PR/` — PR-fix integration tests

`141.fix-26-integration-test.sh` v2.5.0 — exercises the new<br/>
&nbsp; &nbsp; `DELETE /v1/certificate/{issuer_dn}/{serial}` REST endpoint added by<br/>
&nbsp; &nbsp; **PR-fix-26**. Self-prov mode (T1–T9) provisions its own fixtures; BYOC<br/>
&nbsp; &nbsp; mode (`--ee-username + --elt + --reaper-ok`) iterates over existing<br/>
&nbsp; &nbsp; revoked certs from a real-world inventory.

`142.fix-27-integration-test.sh` v1.0.0 — exercises the new DBMS<br/>
&nbsp; &nbsp; Maintenance Worker (`MODE_REVOKED`) added by **PR-fix-27**. Provisions<br/>
&nbsp; &nbsp; 13 test fixtures spanning the E/R/r lifecycle buckets including the<br/>
&nbsp; &nbsp; `status=60` ARCHIVED substate, runs the worker on a 1-minute interval,<br/>
&nbsp; &nbsp; asserts the expected sweep + survivorship pattern (T1–T13).

<br/>

## Status

These scripts are the working set behind two Community Edition pull requests<br/>
&nbsp; &nbsp; from the same single-developer + Claude pair-programming workflow that<br/>
&nbsp; &nbsp; produced [`Keyfactor/ejbca-cert-manager-issuer` PR #129](https://github.com/Keyfactor/ejbca-cert-manager-issuer/pull/129):

- **Fix-27 — DBMS Maintenance Worker** (`MODE_REVOKED` cleanup mode):<br/>
&nbsp; &nbsp; verified via `Bin/140.verify-PR/142.fix-27-integration-test.sh`<br/>
&nbsp; &nbsp; (13/13 PASS).
- **Fix-26 — REST `DELETE /v1/certificate/{issuer_dn}/{serial}`** endpoint:<br/>
&nbsp; &nbsp; verified via `Bin/140.verify-PR/141.fix-26-integration-test.sh`<br/>
&nbsp; &nbsp; (174-cert BYOC + T1–T9 self-prov).

The dated directory name (`2026-06-01.EJBCA-tools/`) pins this snapshot; later<br/>
&nbsp; &nbsp; iterations may live alongside it under their own dated subdirectories<br/>
&nbsp; &nbsp; without breaking inbound links.

Issues, suggestions, and contributions are welcome via the parent<br/>
&nbsp; &nbsp; [`John-D-B/Claudes`](https://github.com/John-D-B/Claudes) repo.
