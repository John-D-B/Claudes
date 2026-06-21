# EJBCA-CE DEMO

*End-to-End Demonstration*

**Author:** JohnB, with AI pair-programming support by Anthropic Claude<br/>
**Date:** 2026-06-21

**Audience:** vendor reviewers and operators who want to reproduce the<br/>
&nbsp; &nbsp; Fix-26 / Fix-27 verification from a fresh clone.

This walkthrough goes from `git clone` to both PR integration tests passing,<br/>
&nbsp; &nbsp; then finishes with the real-world scenario the PRs exist to solve.

**What it proves:**

- **The stack is reproducible:**<br/>
A fresh clone brings up EJBCA-CE + MariaDB and bootstraps mTLS admin access,<br/>
&nbsp; &nbsp; with no admin-GUI clicking required.

- **The PR fixes are verified:**<br/>
Each PR has a black-box integration test that provisions its own fixtures<br/>
&nbsp; &nbsp; and asserts the new behaviour (Fix-27: 13/13 PASS; Fix-26: 9/9 PASS).

- **The PRs solve a measured real-world problem:**<br/>
The finale reproduces cert-manager renewal accumulation,<br/>
&nbsp; &nbsp; measures it, clears it with the Fix-26 endpoint, and confirms the result<br/>
&nbsp; &nbsp; (recorded run: 174-certificate inventory, see Part 5).

## Terminology

- **script group:**<br/>
One of the seven numbered sub-directories under `Bin/`:<br/>
&nbsp; &nbsp; `200.build/`, `210.bootstrap/`, `220.certs/`, `230.rebuild/`,<br/>
&nbsp; &nbsp; `300.cluster/`, `500.verify-PR/`, `900.probes/`.<br/>
Scripts inside a group run in sort order; each is idempotent and rerunnable.

- **self-provision mode:**<br/>
The integration test creates its own test certificates, runs its checks, and cleans up.<br/>
Default mode of both `Bin/500.verify-PR/` tests. Used in Part 4.

- **BYOC mode** ("Bring Your Own Certificates")**:**<br/>
The Fix-26 integration test runs against certificates that already exist<br/>
&nbsp; &nbsp; in the EJBCA database, instead of creating its own. Used in Part 5.

- **Echo-before-run convention:**<br/>
Every script prints each `curl` / `docker` / `keytool` command before executing it,<br/>
&nbsp; &nbsp; so you can copy-paste any single probe and iterate by hand.

<br/><br/><br/><br/><br/><br/>

## Prerequisites

**Parts 1–4:**

- Docker with `docker compose`.
- `bash`, `curl` (stock versions are fine).
- For Part 3 only: OpenJDK 21 and network access — `231.build-local-image.sh`<br/>
&nbsp; &nbsp; clones the upstream EJBCA-CE source and applies the bundled PR patches for you.
- One line in `/etc/hosts` so the scripts' default hostname resolves locally:

```bash
127.0.0.1   host.k3d.internal
```

**Part 5 additionally:**

- `k3d`, `kubectl`, `helm` (the finale runs cert-manager in a local Kubernetes cluster).
- Python 3.8+ with the `pip` requirements installed per `../bin/README.md`<br/>
&nbsp; &nbsp; (the `bin/` `$PATH` setup itself happens in Part 1).

## Part 1: Bring up the Docker stack
"Stack" is Docker's own word for a multi-service Compose/Swarm application.<br/>
The services are defined in `stack/docker-compose.yml`, running together as one unit:
- ejbca (the CE server)
- container: mariadb (state, and with certificates)

```bash
$ git clone https://github.com/John-D-B/Claudes.git
$ cd Claudes/2026-06-01.EJBCA-tools/
$ topDir=$(pwd)
$ export PATH="${topDir}/bin:$PATH"

$ cd ${topDir}/ejbca-ce/
$ cd ./stack/
$ docker compose up -d
```

`topDir` anchors every later section of this walkthrough —<br/>
&nbsp; &nbsp; each Bash block starts with a `cd ${topDir}/...` so it works regardless<br/>
&nbsp; &nbsp; of where your shell wandered in between.

The `PATH` export makes the bundled tools callable by name in Part 5:
- **DEK:** &nbsp; `deploy_ejbca_k8s.py`
- **ELT:** &nbsp; &nbsp; `ejbca-lifecycle-tool.py`
- **CG:** &nbsp; &nbsp; `cert-grep.py` &nbsp; \& &nbsp; `ssl-grep.py`

Two Docker containers start: `mariadb` (state) and `ejbca` (the CE server).<br/>
The first boot takes a few minutes while EJBCA initializes its database.

## Part 2: One-time setup (script group: `210.bootstrap/`)

```bash
$ cd ${topDir}/ejbca-ce/
$ for s in ./Bin/210.bootstrap/*.sh; do "$s" || break; done
```

Or build the server from scratch in one step — `Bin/200.build/201.build-server.sh`<br/>
&nbsp; &nbsp; wipes and re-creates the stack, waits for readiness, then runs this group<br/>
&nbsp; &nbsp; (it replaces Parts 1–2).

The group runs in sort order and leaves you with working mTLS admin access:

- `211` verifies the stack is healthy (admin GUI answers `200`).
- `212` re-issues the auto-bootstrapped SuperAdmin as a long-lived admin.
- `213` enables EJBCA's REST API protocols (CE ships them disabled).
- `214` creates and enrols a dedicated `ELT-Admin` client cert.
- `215`–`216` populate the server truststore and verify mTLS REST access end-to-end.
- `217`–`218` import the demo's End Entity + Certificate profiles and verify them via SOAP.
- `219` re-issues the server TLS cert with reachable SANs.

Credentials land on the host under `Creds/elt/` (git-ignored) and are reused<br/>
&nbsp; &nbsp; by every later part — across rebuilds, restarts, and reboots.

Quick health check at any time:

```bash
$ cd ${topDir}/ejbca-ce/
$ ./Bin/900.probes/901.smoke-test.sh --target ce      # expect: 5/5 PASS
```

## Part 3: Build the PR code into the stack (`230.rebuild/`)

```bash
$ cd ${topDir}/ejbca-ce/
$ ./Bin/230.rebuild/231.build-local-image.sh          # gradle build + docker wrap
$ ./Bin/230.rebuild/232.swap-stack-image.sh ejbca-ce:local-fixes
```

`231` clones the upstream EJBCA-CE source, applies the bundled Fix-26 / Fix-27 patches,<br/>
&nbsp; &nbsp; builds the EAR, and wraps it onto the `keyfactor/ejbca-ce` base image as `ejbca-ce:local-fixes`.<br/>
`232` swaps the running stack onto that image.

To revert to the upstream image later:

```bash
$ ./Bin/230.rebuild/232.swap-stack-image.sh keyfactor/ejbca-ce:latest
```

## Part 4: Verify both PRs (`500.verify-PR/`)

Run Fix-27 first (Fix-26 builds on its EJB primitive):

```bash
$ cd ${topDir}/ejbca-ce/
$ ./Bin/500.verify-PR/502.fix-27-integration-test.sh
```

**Expected: 13/13 PASS.**<br/>
The test enrolls fixtures across the certificate lifecycle states,<br/>
&nbsp; &nbsp; installs the new Database Maintenance Worker on a 1-minute schedule,<br/>
&nbsp; &nbsp; waits ~80 seconds for one worker run, and asserts the sweep-and-survivors pattern —<br/>
&nbsp; &nbsp; including the `status=60` archived case and the reason-code filter.

```bash
$ cd ${topDir}/ejbca-ce/
$ ./Bin/500.verify-PR/501.fix-26-integration-test.sh
```

**Expected: 9/9 PASS.**<br/>
The test enrolls fresh end entities and walks the new REST endpoint through<br/>
&nbsp; &nbsp; its full response surface:<br/>
&nbsp; &nbsp; `204` delete of a revoked cert, `404` after deletion, `404` on a bogus serial,<br/>
&nbsp; &nbsp; and the `409` guard that refuses to delete an unrevoked cert.

Test plans with per-case rationale: `Docs/ejbca-ce-task-3.5-fix-27-test-plan.md`<br/>
&nbsp; &nbsp; and `Docs/ejbca-ce-task-3.7-fix-26-test-plan.md`.

## Part 5: The real-world finale (BYOC mode)

Parts 1–4 prove the fixes work. This part shows **why they matter**.

**The problem being reproduced:**<br/>
When Kubernetes cert-manager "renews" a certificate, it does not extend the old one.<br/>
It issues a brand-new certificate and the old one is revoked<br/>
&nbsp; &nbsp; (automatically, when the EJBCA profile sets Single Active Certificate Constraint).<br/>
Each revoked predecessor keeps its original expiry date,<br/>
&nbsp; &nbsp; so frequent renewals pile up revoked-but-unexpired records<br/>
&nbsp; &nbsp; that EJBCA's stock maintenance cannot purge until they expire — possibly years later.

### 5.1: Deploy cert-manager against the stack

```bash
$ cd ${topDir}/ejbca-ce/
$ deploy_ejbca_k8s.py --help
    ...
$ deploy_ejbca_k8s.py set --preset local-fixes
$ deploy_ejbca_k8s.py show
$ deploy_ejbca_k8s.py do
```

`set` writes the configuration; `show` prints what resolved (CA name, profiles,<br/>
&nbsp; &nbsp; credential paths) so you can sanity-check before `do` touches the cluster.<br/>
`do` installs cert-manager + the EJBCA cert-manager-issuer into a local cluster<br/>
&nbsp; &nbsp; and issues one certificate end-to-end against the CE stack.<br/>
Details and configuration: `../dek/README-deploy-ejbca-k8s.md`.

### 5.2: Reproduce the renewal accumulation

```bash
$ cd ${topDir}/ejbca-ce/
$ export BD_SECRET_NAME=RANDOM
$ deploy_ejbca_k8s.py do      # repeat several times
```

`RANDOM` is a special token, not a literal name:<br/>
&nbsp; &nbsp; **DEK** (deploy_ejbca_k8s.py) appends a fresh 4-digit suffix to the *Secret* name on every run,<br/>
&nbsp; &nbsp; which cert-manager treats as a new Secret to fill — forcing a re-issuance each time.

The End Entity stays the same throughout:<br/>
&nbsp; &nbsp; the issuer derives the EE username from the certificate's CN, which doesn't change,<br/>
&nbsp; &nbsp; so every re-issuance lands on one EE and revokes its predecessor.<br/>
Repeat until you have a satisfying pile.

### 5.3: Measure it

```bash
$ cd ${topDir}/ejbca-ce/

$ ejbca-lifecycle-tool.py --help
    ...
    status codes (cert table 'S' column and count-line breakdown):
    A   active                  — certificate is not revoked, not expired
    E   expired (not revoked)   — cert is past notAfter, never revoked
    R   revoked + expired       — cert is revoked AND past notAfter (prunable from CRL)
    r   revoked + unexpired     — cert is revoked, still within validity (CRL must carry)
    ?   unknown                 — status doesn't map to the four above

$ ejbca-lifecycle-tool.py count
$ ejbca-lifecycle-tool.py list4
```

**ELT**'s status codes for what you'll see:<br/>
&nbsp; &nbsp; `A` active, `E` expired, `R` revoked + expired, `r` revoked + unexpired.<br/>
The `r` records are the accumulation — formally valid, revoked, and unpurgeable until expiry.

Note the **End Entity username** of your demo certificate in the `list4` output —<br/>
&nbsp; &nbsp; step 5.4 needs it.<br/>
(EE username is an EJBCA database identity, distinct from the cert's CN in general;<br/>
&nbsp; &nbsp; for **DEK**-issued certs they match, because the issuer derives the EE username from the CN.)

### 5.4: Clear it with the Fix-26 endpoint

```bash
$ cd ${topDir}/ejbca-ce/
$ ./Bin/500.verify-PR/501.fix-26-integration-test.sh \
    --ee-username <EE-username-from-5.3> --elt --reaper-ok
```

BYOC mode discovers the End Entity's revoked serials via ELT,<br/>
&nbsp; &nbsp; deletes each through the new `DELETE /v1/certificate/{issuer_dn}/{serial}` endpoint,<br/>
&nbsp; &nbsp; verifies each deletion, and proves the active cert is refused with a `409`.<br/>
(`--reaper-ok` acknowledges the DBMS worker is INACTIVE,<br/>
&nbsp; &nbsp; so it can't sweep certs out from under the assertions.)

### 5.5: Confirm

```bash
$ cd ${topDir}/ejbca-ce/
$ ejbca-lifecycle-tool.py count     # revoked records: gone; active cert: intact
```

### The recorded run

This sequence was executed against a corpus accumulated over several days<br/>
&nbsp; &nbsp; of real cert-manager renewal cycles, on EJBCA CE 9.3.7 + both PRs:

| Step | Result |
|---|---|
| Inventory before | **174 certificates**: 1 `A` active, 167 `R` revoked+expired, 6 `r` revoked+unexpired |
| DELETE on each revoked serial | **173 × HTTP 204** |
| Post-delete verification | **173 × HTTP 404** (rows genuinely gone) |
| Bogus-serial probe | **1 × HTTP 404** |
| Active-cert guard | **1 × HTTP 409** (delete refused; revoke-first workflow enforced) |
| Inventory after | **1 active certificate** — nothing else |

All assertions PASS, in a single run.

## Where to go next

- `README-ejbca-ce.md` — full reference for the stack and every script group.
- `Docs/` — PR design docs, test plans, GUI mockup, and the CE REST gap analysis.
- `../elt/README-elt.md` — the certificate-lifecycle story behind the accumulation problem.
- `../dek/README-deploy-ejbca-k8s.md` — the deploy tool in depth (28 steps, all logged).
- `../cg/README-cert-grep.md` — inspect any certificate this demo produces.
