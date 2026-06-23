# EJBCA CE — Task 3.5: Fix 27 Integration Test Plan

**Author:** John Buehrer (JohnB), with AI pair-programming support by Anthropic Claude
<br/>
**Date:** 2026-05-23 (revised 2026-06-02 — radio-mode refactor + status-60 fix)

**Purpose:** Validate the new MODE_REVOKED capability that task 3.4 added<br/>
&nbsp; &nbsp; to the `DatabaseMaintenanceWorker`. Under MODE_REVOKED, the worker<br/>
&nbsp; &nbsp; deletes every certificate whose revocation reason is in the operator-<br/>
&nbsp; &nbsp; selected set, regardless of expiry or archival state.

`Bin/500.verify-PR/502.fix-27-integration-test.sh` exercises **13 test cases:**

- **T1–T9** — MODE_REVOKED basic reason-filter behavior: three EEs<br/>
&nbsp; &nbsp; (two SUPERSEDED, one KEY_COMPROMISE), pre-sweep visibility check,<br/>
&nbsp; &nbsp; worker install, single tick, post-sweep assertions. The SUPERSEDED<br/>
&nbsp; &nbsp; rows are reaped; the KEY_COMPROMISE row survives — reason filter works.
- **T10–T13** — MODE_REVOKED lifecycle-bucket coverage: four fresh fixtures<br/>
&nbsp; &nbsp; probing the buckets E/r/R-status-40/R-status-60 under one worker tick.<br/>
&nbsp; &nbsp; T10 (R-status-40), T11 (R-status-60), T12 (r) are reaped; T13 (E)<br/>
&nbsp; &nbsp; survives. T11 specifically locks in the design fix for status=60<br/>
&nbsp; &nbsp; archived rows that the original `status = REVOKED` formulation<br/>
&nbsp; &nbsp; silently excluded.

## Prerequisites

The stack is running the `ejbca-ce:local-fixes` image (Phase 3 work is baked<br/>
&nbsp; &nbsp; in). The admin GUI is reachable at<br/>
&nbsp; &nbsp; `https://host.k3d.internal:8443/ejbca/adminweb/` using the<br/>
&nbsp; &nbsp; `ce-eltadmin.p12` client cert.

## Fixture note

TwoSter's 5 SUPERSEDED records from Phase 2.5 would be valid input — but they<br/>
&nbsp; &nbsp; sit in a shared corpus that other tests may touch, so the rig produces<br/>
&nbsp; &nbsp; its own dedicated fixtures to keep PASS/FAIL deterministic per run.

The fix-27 worker filter is `status=REVOKED AND revocationReason IN :reasons`<br/>
&nbsp; &nbsp; — `expireDate` is not part of the filter, so both still-valid and<br/>
&nbsp; &nbsp; already-expired revoked rows are in scope as long as the reason matches.<br/>
&nbsp; &nbsp; (Design rationale in `Docs/ejbca-ce-task-3.4-dbms-worker-design.md` and<br/>
&nbsp; &nbsp; the *Motivation* section of `Docs/PR-fix-27-dbms-worker-revoked-certs.md`<br/>
&nbsp; &nbsp; — the customer driver produces revoked rows with `expireDate` years out<br/>
&nbsp; &nbsp; thanks to the profile-Validity-maximum cert-manager-issuer bug.)

The test produces three fresh fixtures with multi-year validity, which makes<br/>
&nbsp; &nbsp; the worker's behaviour reason-driven and time-independent during the<br/>
&nbsp; &nbsp; ~80-second test window.

## Test design

Three end entities, two revocation reasons, one worker run:

| Fixture | Revocation | Worker should | Why |
|---|---|---|---|
| `dbms-superseded-A-<ts>` | SUPERSEDED | delete | matches reason filter |
| `dbms-superseded-B-<ts>` | SUPERSEDED | delete | matches reason filter |
| `dbms-keycompromise-<ts>` | KEY_COMPROMISE | keep | wrong reason — control |

The third row is the negative control. Its survival proves the worker isn't<br/>
&nbsp; &nbsp; deleting indiscriminately; only the reason-matched rows go.

## Step-by-step

### 1. Enroll the three fixtures

Inside the EJBCA container, via `ejbca.sh ra`:

```sh
# from project root
cd stack
TS=$(date +%Y%m%d-%H%M%S)
for who in "dbms-superseded-A-$TS" "dbms-superseded-B-$TS" "dbms-keycompromise-$TS" ; do
    docker compose exec -T ejbca /opt/keyfactor/bin/ejbca.sh ra addendentity \
        --username "$who" --dn "CN=$who" --caname ManagementCA \
        --type 1 --token P12 --password testpwd35 \
        --certprofile ENDUSER --eeprofile EMPTY
    docker compose exec -T ejbca /opt/keyfactor/bin/ejbca.sh ra setclearpwd "$who" testpwd35
    docker compose exec -T ejbca /opt/keyfactor/bin/ejbca.sh batch "$who"
done
```

The default ENDUSER profile issues with multi-year validity, well past the<br/>
&nbsp; &nbsp; worker-run timestamp.

### 2. Revoke with specific reasons

```sh
docker compose exec -T ejbca /opt/keyfactor/bin/ejbca.sh ra revokeuser \
    "dbms-superseded-A-$TS" 4    # 4 = SUPERSEDED
docker compose exec -T ejbca /opt/keyfactor/bin/ejbca.sh ra revokeuser \
    "dbms-superseded-B-$TS" 4
docker compose exec -T ejbca /opt/keyfactor/bin/ejbca.sh ra revokeuser \
    "dbms-keycompromise-$TS" 1   # 1 = KEY_COMPROMISE
```

RFC 5280 reason codes: `0=unspecified, 1=keyCompromise, 4=superseded, ...` —<br/>
&nbsp; &nbsp; see `RevocationReasons.java` in the source tree for the full list.

### 3. Configure the worker via the admin GUI

Open `https://host.k3d.internal:8443/ejbca/adminweb/` → **Services** in the<br/>
&nbsp; &nbsp; left nav. Add a new service named e.g. `FixTwentySevenTest`:

- **Select Worker:** *Database Maintenance Worker*
- **Period:** 1 minute (Periodical Interval, value=1, unit=MINUTES)
- **Action:** No Action
- **Database Maintenance Worker Settings:**
  - **CAs To Check:** ManagementCA
  - **Certificate deletion mode:** *Delete revoked certificates* (ELT: r + R)
  - **Delay After Revocation:** 0 (no quarantine)
  - **Revocation Reasons:** `SUPERSEDED`
  - **Delete Expired CRLs:** unchecked
  - **Entries to delete per run:** 100
- **Active:** ✅

Save. Within ~60 seconds the worker should tick.

### 4. Verify the outcome

```sh
docker compose exec -T mariadb mariadb -uejbca -pejbca ejbca -e \
    "SELECT username, revocationReason FROM CertificateData
     WHERE username LIKE 'dbms-%-$TS';"
```

Expected result table:

| `username` | `revocationReason` | rationale |
|---|---|---|
| `dbms-keycompromise-<ts>` | 1 | kept — reason filter excludes it |

The two SUPERSEDED rows must be absent from the result set. A direct `COUNT(*)`<br/>
&nbsp; &nbsp; query against the same `WHERE` works as a one-shot pass/fail check.

### 5. Cleanup

Stop the service (mark `Active: ☐` in the admin GUI, or delete it outright)<br/>
&nbsp; &nbsp; so it doesn't continue running every minute. Revoke and delete the<br/>
&nbsp; &nbsp; remaining end entity if you want a fully clean run.

## Observing the worker in flight

EJBCA's admin GUI doesn't surface "next-run" / "last-run" indicators on<br/>
&nbsp; &nbsp; the Manage Services page, so operators inspecting an in-flight worker<br/>
&nbsp; &nbsp; have three practical observation paths. All three are read-only —<br/>
&nbsp; &nbsp; useful for confirming the worker is ticking, seeing which rows it<br/>
&nbsp; &nbsp; deletes, and matching deletion timestamps against the cert-side<br/>
&nbsp; &nbsp; data you queried via ELT or the admin GUI.

### Path A — Admin GUI Audit Log (most operator-friendly)

*Supervision Functions → Audit Log* → filter `Event = CERT_CLEANUP`.<br/>
&nbsp; &nbsp; Every deletion is a row with timestamp, serial number, CA ID,<br/>
&nbsp; &nbsp; username, and the localized message (`Deleted revoked certificate<br/>
&nbsp; &nbsp; with serial number ... and CA ID ...` for MODE_REVOKED, or<br/>
&nbsp; &nbsp; `Deleted expired certificate ...` for MODE_EXPIRED). No shell access<br/>
&nbsp; &nbsp; needed; canonical operator view.

### Path B — Container log live tail (best for "is it ticking right now")

```sh
mac$ docker compose -f stack/docker-compose.yml logs -f --since=1m ejbca \
       | grep -iE 'Reaper|DatabaseMaintenance|store\.deleted'
```

Each tick prints three event types:

- `Timer was triggered. Trying to run service with ID ...` — the
   underlying Jakarta EE Timer firing.
- `Attempting to run service: <Service Name>` — about to invoke `work()`.
- `Service <Service Name> executed with the following result: ...
   deleted N certificate(s) matching criteria, M expired CRL(s).`
- Plus one `CERT_CLEANUP;SUCCESS;...store.deletedrevokedcert` (or
   `store.deletedexpiredcert`) line per deleted row.

The `-f` keeps the tail open; `--since=1m` skips ancient backlog. The
`grep` filter avoids noise from the rest of WildFly.

### Path C — Recent-history one-shot scan (best for "did anything tick lately")

```sh
mac$ docker compose -f stack/docker-compose.yml logs --since=10m ejbca \
       | grep 'Service .* executed'
```

Returns one line per worker tick (any worker, not just the reaper) with
its summary string. Use this to spot-check that the reaper ran on
schedule without committing a terminal to a live tail.

### Path D — DB-poll loop (best for "exit when the work is done")

If you only care about the outcome — e.g. *"how many SUPERSEDED-revoked
zombies are left for this end entity?"* — the cleanest way is to poll
the histogram until it reaches the target state:

```sh
mac$ until docker compose -f stack/docker-compose.yml exec -T mariadb \
       mariadb --table -uroot -prootpw -D ejbca -e \
       "SELECT status, revocationReason, COUNT(*) AS n FROM CertificateData
        WHERE username='YOUR-EE-USERNAME' GROUP BY status, revocationReason"; \
       sleep 5; done
```

Exit the loop with Ctrl-C once you see what you want. The `--table` flag
renders the output as ASCII box-tables instead of bare TSV.

## Pass criteria

- Exactly two rows deleted (both `dbms-superseded-*-<ts>`).
- The `dbms-keycompromise-<ts>` row survives.
- EJBCA server log shows `INFO ...DatabaseMaintenanceWorker... deleted 2`<br/>
&nbsp; &nbsp; revoked certificate(s) lines from the worker run.

If any of these three checks fail, fix 27 has a bug.

## Out of scope (for this PR)

- The CRL-deletion branch — covered by the existing upstream logic;
   our worker just calls the existing CRL session bean for that branch.
- Audit-log correctness — verified manually from the docker container
   log; the `store.deletedrevokedcert` and `store.deletedexpiredcert`
   messages appear with the expected format-string substitutions. Not
   gated by an assertion.

## T10–T13 — MODE_REVOKED lifecycle-bucket coverage

Four assertions in `Bin/500.verify-PR/502.fix-27-integration-test.sh` that lock in the<br/>
&nbsp; &nbsp; MODE_REVOKED radio's behavior across the full E/r/R-status-40/R-status-60<br/>
&nbsp; &nbsp; lifecycle buckets. Run together with T1–T9 under the **same** worker<br/>
&nbsp; &nbsp; (`Fix27Test-<runtag>` with `certDeletionMode=REVOKED`,<br/>
&nbsp; &nbsp; reasons=SUPERSEDED, revoke-delay=0).

Four fresh fixtures probe each bucket:

- **T10 — `R-status-40` reaped.** Fixture is SUPERSEDED-revoked + its<br/>
&nbsp; &nbsp; `expireDate` is backdated to epoch+1ms via direct MariaDB UPDATE.<br/>
&nbsp; &nbsp; status=40 + reason=4 + past-expiry → match → reaped on next tick.<br/>
&nbsp; &nbsp; Verified via the REST `/revocationstatus` endpoint returning HTTP 404.
- **T11 — `R-status-60` reaped.** Fixture is SUPERSEDED-revoked +<br/>
&nbsp; &nbsp; backdated `expireDate` + an additional<br/>
&nbsp; &nbsp; `UPDATE CertificateData SET status=60` that simulates what EJBCA's<br/>
&nbsp; &nbsp; post-expiry housekeeping does over time. status=60 + reason=4 →<br/>
&nbsp; &nbsp; match (via the widened `status IN (40, 60)` filter) → reaped.<br/>
&nbsp; &nbsp; **This is the design-fix-locking assertion** — without the widened<br/>
&nbsp; &nbsp; status filter introduced in this PR, the row would silently survive<br/>
&nbsp; &nbsp; and operators would accumulate unreapable zombies on long-running<br/>
&nbsp; &nbsp; stacks.
- **T12 — `r` reaped.** Fixture is SUPERSEDED-revoked, no backdate<br/>
&nbsp; &nbsp; (`expireDate` stays multi-year-future). status=40 + reason=4 +<br/>
&nbsp; &nbsp; recent revocationDate → match → reaped. Proves the cert-manager-issuer<br/>
&nbsp; &nbsp; pre-v2.2.0 / long-Validity bucket is in scope.
- **T13 — `E` survives.** Fixture is enrolled but **not** revoked;<br/>
&nbsp; &nbsp; `expireDate` backdated. status=20 (ACTIVE), reason=-1 (NOT_REVOKED)<br/>
&nbsp; &nbsp; — reason filter excludes it → row survives. Verified via HTTP 200<br/>
&nbsp; &nbsp; with `revoked=false`. Confirms MODE_REVOKED doesn't accidentally<br/>
&nbsp; &nbsp; sweep naturally-expired non-revoked rows (which belong to MODE_EXPIRED).

Together T10/T11/T12/T13 establish that MODE_REVOKED catches every<br/>
&nbsp; &nbsp; revoked-by-reason bucket regardless of expiry or archival state, and<br/>
&nbsp; &nbsp; only those buckets.

Last operator run: **13/13 PASS** on `ejbca-ce:local-fixes`.

Together T10/T11/T12 prove the JPQL builder composes the criteria
correctly: each clause is necessary, both clauses together suffice.

## Two-track test methodology

The same Fix 27 behaviour is validated along two complementary tracks.<br/>
Each track serves a different audience and surfaces a different class of issue.<br/>
Operators get a transparent end-to-end story they can reproduce by hand.

The Claude pair-programming pipeline gets a deterministic regression rig<br/>
&nbsp; &nbsp; that exercises edge cases the GUI can't reach in a sensible amount of time.

### Track 1 — Manual GUI walkthrough (operator-facing)

The step-by-step recipe above (sections *1. Enroll the three fixtures*<br/>
&nbsp; &nbsp; through *5. Cleanup*) is meant to be **run by a human operator**<br/>
&nbsp; &nbsp; using the EJBCA admin GUI plus `ejbca.sh` CLI commands inside the<br/>
&nbsp; &nbsp; running container.

The point is **full awareness**.

An EJBCA administrator deploying this PR into their environment should be<br/>
&nbsp; &nbsp; able to read the recipe, perform every step against their own stack,<br/>
&nbsp; &nbsp; see the worker configuration form (per `Docs/fix27-gui-mockup.png`),<br/>
&nbsp; &nbsp; watch the worker tick, and verify the cleanup happened — all without<br/>
&nbsp; &nbsp; trusting any opaque automation.

This track also doubles as the operational reference for diagnosing a<br/>
&nbsp; &nbsp; misconfigured worker in production: every assertion is something an<br/>
&nbsp; &nbsp; operator can replicate at their own console.

### Track 2 — Scripted regression rig (Claude-facing)

The companion script `Bin/500.verify-PR/502.fix-27-integration-test.sh` exercises the same<br/>
&nbsp; &nbsp; behaviour end-to-end without a human in the loop.

It uses `ejbca.sh service create` to install the worker with a 1-minute<br/>
&nbsp; &nbsp; periodic interval, sleeps ~80 seconds for one tick, and verifies via<br/>
&nbsp; &nbsp; the REST `/revocationstatus` endpoint.

T1–T9 land via this track. The planned T10–T12 will land via the same path, with the addition of a<br/>
&nbsp; &nbsp; per-fixture helper to backdate rows into the *expired* bucket without waiting for clock time to pass:

`->     UPDATE CertificateData SET expireDate=1`


Direct DB writes like that are precisely the kind of under-the-hood<br/>
&nbsp; &nbsp; manipulation a human operator would never do in production but a<br/>
&nbsp; &nbsp; regression rig needs to do routinely to keep the test deterministic<br/>
&nbsp; &nbsp; and fast.

The Claude session(s) running this PR's CI loop are the primary consumers<br/>
&nbsp; &nbsp; of Track 2 — the rig is what we run before every commit to catch<br/>
&nbsp; &nbsp; behaviour regressions inside the EJBCA build, and what we'd extend if<br/>
&nbsp; &nbsp; reviewers ask for additional assertions.

### Why both

The two tracks aren't redundant. They cover complementary failure modes.

Track 1 catches *operator-experience* problems: missing labels, confusing<br/>
&nbsp; &nbsp; defaults, fields that don't persist, GUI-form layout bugs, audit-log<br/>
&nbsp; &nbsp; messages that don't read right at 3 a.m. when an operator is<br/>
&nbsp; &nbsp; diagnosing live data loss.

Track 2 catches *behaviour* regressions: a JPQL clause builder that quietly<br/>
&nbsp; &nbsp; drops a parameter, a status-dispatch logic error, a property-bag<br/>
&nbsp; &nbsp; round-trip failure.

Both have to pass before this PR is considered ready, and both would pass<br/>
&nbsp; &nbsp; again before any follow-up change ships.
