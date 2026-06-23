# EJBCA CE — Task 3.4: `DatabaseMaintenanceWorker` Design (with fix 27)

**Author:** JohnB, with AI pair-programming support by Anthropic Claude
<br/>
**Date:** 2026-05-22 (revised 2026-06-02 — see banner below)

> <br/>**Design: Radio buttons + status=60**<br/>
> Mutually-exclusive radio-mode selection:<br/>
> &nbsp; &nbsp; *Delete expired certificates* | *Delete revoked certificates* | *None (CRL deletions only)*.<br/>
> 
> The radio modes map directly to the certificate lifecycle buckets:<br/>
> &nbsp; &nbsp; `E` expired, `r` revoked + unexpired, `R` revoked + expired<br/>
>
> The MODE_REVOKED branch uses this:<br/>
> &nbsp; &nbsp; `status IN (CERT_REVOKED, CERT_ARCHIVED)`<br/>
>
> This is the critical fix that lets the reaper reach status=60 archived rows.<br/>
> Without it, EJBCA's normal post-expiry housekeeping silently produces<br/>
> &nbsp; &nbsp; unreapable accumulations on long-running stacks.
>
> Canonical references for the current design:<br/>
> - the Fix-27 PR description
> - `fix27-gui-mockup.png` (GUI mockup)
> - `Bin/500.verify-PR/502.fix-27-integration-test.sh` : tests T10–T13
> 
> <br/>

<br/>

**Purpose:**<br/>
Design the Fix-27 work before any source edits:<br/>
&nbsp; &nbsp; create a `DatabaseMaintenanceWorker` class for EJBCA CE,<br/>
&nbsp; &nbsp; and within it implement the new "Delete Revoked Certificates" capability.

## The two problems

**Problem 1 — CE has no DBMS Worker at all.**<br/>
EJBCA CE ships `DatabaseMaintenanceWorkerConstants.java` and `DatabaseMaintenanceWorkerType.java`,<br/>
&nbsp; &nbsp; but the actual worker class —<br/>
&nbsp; &nbsp; `org.ejbca.core.model.services.workers.DatabaseMaintenanceWorker` — is EE-only.<br/>
Configuring the service via the admin GUI on a CE deployment today<br/>
&nbsp; &nbsp; fails at runtime with a `ClassNotFoundException`.<br/>
Confirmed by full source-tree and deployed-jar inspection.

**Problem 2 — Even EE's existing worker only handles *expired* deletions.**<br/>
Per the existing constants in CE, the only properties defined today are<br/>
&nbsp; &nbsp; `deleteExpiredCertificates` and `deleteExpiredCrls`.<br/>
There is no facility for deleting *revoked-by-reason* records.<br/>
These are precisely the rows that cert-manager renewal accumulation produces:<br/>
&nbsp; &nbsp; revoked, with `expireDate` set to the profile maximum (often years in the future),<br/>
&nbsp; &nbsp; so the existing expired-only branch can never reach them.<br/>
That gap is **fix request 27**.

The design addresses both problems, but keeps them cleanly separable —<br/>
&nbsp; &nbsp; so the vendor's EE team can adopt just the Fix-27 contribution<br/>
&nbsp; &nbsp; without touching their existing worker implementation.

## The two layers of implementation

### Layer A — CE parity (the worker class itself)

Write the `DatabaseMaintenanceWorker` class from scratch,<br/>
&nbsp; &nbsp; so CE deployments can use the worker the admin GUI already advertises.

Behavior: honor the existing expired-cleanup capability<br/>
&nbsp; &nbsp; exactly as a customer would expect from EJBCA documentation.

This layer ships in the PR — without it, the feature cannot run in CE at all.<br/>
The EE codebase is a different story:<br/>
&nbsp; &nbsp; EE already has its own worker class, so Layer A is reference material there,<br/>
&nbsp; &nbsp; and the EE-relevant contribution is isolated in Layer B.

### Layer B — Fix 27 contribution (cleanly upstreamable)

Add the new "Delete Revoked Certificates" capability that fix 27 specifies.<br/>
Designed to be **drop-in adoptable by Keyfactor's EE team**<br/>
&nbsp; &nbsp; as a small, surgical addition to their existing worker.

Concrete pieces:

- **New EJB primitive** on `CertificateStoreSessionLocal` / `Bean`:<br/>
`deleteRevokedCertificatesInSeparateTransactions(...)`,<br/>
&nbsp; &nbsp; mirroring the existing `deleteExpiredCertificatesInSeparateTransactions(...)`<br/>
&nbsp; &nbsp; shape that's already in CE.

- **New property constants** in `DatabaseMaintenanceWorkerConstants`:<br/>
`PROP_DELETE_REVOKED_CERTIFICATES` (bool)<br/>
&nbsp; &nbsp; and `PROP_REVOCATION_REASONS`<br/>
&nbsp; &nbsp; (comma-separated RFC 5280 names, default `"SUPERSEDED"`).

- **New admin-GUI fields** in `DatabaseMaintenanceWorkerType` and the service-config JSF page:<br/>
mirror the existing "Delete Expired Certificates" row layout;<br/>
&nbsp; &nbsp; add a "Revocation Reasons" multi-select.

- **New worker `work()` branch:**<br/>
when revoked-deletion is selected, invoke the new EJB primitive<br/>
&nbsp; &nbsp; with the configured reason filter.<br/>
This is the chunk of code the vendor would graft into their existing worker.

## The two adoption tracks

**Track 1 — the CE repository (this PR):**<br/>
Takes the full set, Layer A + Layer B.<br/>
The worker class is included because CE has no worker class at all;<br/>
&nbsp; &nbsp; the feature is not runnable in CE without it.

**Track 2 — the vendor's EE codebase (their internal merge):**<br/>
EE already has its own worker class, so the EE team grafts only the Layer B pieces:

- New EJB primitive (interface + bean impl) for `deleteRevokedCertificatesInSeparateTransactions`
- New constants (the two `PROP_*` strings and any `DEFAULT_*` values)
- New `DatabaseMaintenanceWorkerType` fields + setter/getter/properties wiring
- The new JSF page section for the admin-GUI form
- The `work()` method branch that invokes the new primitive

What the EE side ignores (because they already have it):

- The worker class itself — they have their own EE version
- All expired-cleanup handling logic — already in their worker

This split keeps the EE-side merge small and surgical,<br/>
&nbsp; &nbsp; while the CE side gains a complete, working feature.

## Design constraints (EJBCA-house-style compatibility)

- **FQCN**<br/>
Matches `Constants.WORKER_CLASS` exactly:<br/>
&nbsp; &nbsp; `org.ejbca.core.model.services.workers.DatabaseMaintenanceWorker`

- **Module:**<br/>
`ejbca-common-web` (same as siblings `HsmKeepAliveWorker`, etc.)

- **License header:**<br/>
Standard EJBCA CE LGPL block (matches sibling workers)

- **Base class:**<br/>
`extends BaseWorker` (which implements `IWorker`)

- **Required overrides:**<br/>
`canWorkerRun(Map<Class<?>, Object> ejbs)` and<br/>
&nbsp; &nbsp; `work(Map<Class<?>, Object> ejbs) → ServiceExecutionResult`

- **Logging:**<br/>
`Logger.getLogger(DatabaseMaintenanceWorker.class)` with<br/>
&nbsp; &nbsp; `log.isDebugEnabled()` guards on hot paths

- **Property naming:**<br/>
camelCase in `PROP_*` values (matches existing)

- **Result reporting:**<br/>
`ServiceExecutionResult` with `Result.NO_ACTION` / success \& failure categories

## EJB primitive design (the deepest piece)

Add to `cesecore-ejb-interface/.../CertificateStoreSessionLocal.java`:

```java
/**
 * Delete revoked certificate rows (status=REVOKED) whose revocationReason
 * is in the supplied set, regardless of expireDate. Runs in separate
 * transactions per batch to avoid long locks. Returns the set of issuer
 * DNs whose certificates were affected, for downstream cache invalidation
 * or auditing.
 *
 * @param issuerDns                 limit deletion to these issuers (null = all)
 * @param revocationReasons         RFC 5280 reason codes to match
 * @param batchSize                 rows per transaction
 * @param adminForLogging           audit-log identity
 */
Set<String> deleteRevokedCertificatesInSeparateTransactions(
        List<String> issuerDns,
        Set<RevocationReasons> revocationReasons,
        int batchSize,
        AuthenticationToken adminForLogging);
```

(Per the 2026-06-02 banner above, the shipped implementation widens the status match<br/>
&nbsp; &nbsp; to `status IN (REVOKED, ARCHIVED)`.)

Implementation in `cesecore-ejb/.../CertificateStoreSessionBean.java`<br/>
&nbsp; &nbsp; follows the existing `deleteExpiredCertificatesInSeparateTransactions` template:<br/>
&nbsp; &nbsp; JPA query for matching rows, batched DELETE in nested-transaction calls,<br/>
&nbsp; &nbsp; audit log per deletion.

## Files touched

| File | Action | Notes |
|---|---|---|
| `…/workers/DatabaseMaintenanceWorker.java` | **New** (~200 lines) | Layer A — CE parity. EE side keeps its own class. |
| `…/workers/DatabaseMaintenanceWorkerConstants.java` | Edit (+5 lines) | Layer B — vendor drop-in. |
| `…/servicetypes/DatabaseMaintenanceWorkerType.java` | Edit (+25 lines) | Layer B — vendor drop-in. |
| `cesecore-ejb-interface/…/CertificateStoreSessionLocal.java` | Edit (+15 lines) | Layer B — vendor drop-in. |
| `cesecore-ejb/…/CertificateStoreSessionBean.java` | Edit (+50 lines) | Layer B — vendor drop-in. |
| `…/admin-gui/.../service-config.xhtml` (or equivalent) | Edit (+20 lines) | Layer B — vendor drop-in. |

Total: one new class, one new EJB method (interface + implementation),<br/>
&nbsp; &nbsp; three Java edits, one JSF edit.<br/>
About 300 lines of new or changed code.

## Implementation order (sub-steps of task 3.4)

- **3.4a** Add `deleteRevokedCertificatesInSeparateTransactions(...)` to the<br/>
&nbsp; &nbsp; EJB interface + bean. Build to verify compile.<br/>
&nbsp; &nbsp; (Foundation primitive; Layer B; architecturally the deepest piece.)

- **3.4b** Add `PROP_DELETE_REVOKED_CERTIFICATES` + `PROP_REVOCATION_REASONS`<br/>
&nbsp; &nbsp; constants in `DatabaseMaintenanceWorkerConstants`. (Layer B.)

- **3.4c** Write `DatabaseMaintenanceWorker.java` from scratch.<br/>
&nbsp; &nbsp; (Layer A; integrates Layer B's primitive for the revoked-deletion branch.)

- **3.4d** Extend `DatabaseMaintenanceWorkerType` with the new fields. (Layer B.)

- **3.4e** Update the admin-GUI JSF page. (Layer B.)

- **3.4f** `./gradlew -x test build` — verify clean compile end-to-end.

The integration test follows the implementation:<br/>
&nbsp; &nbsp; plan in `ejbca-ce-task-3.5-fix-27-test-plan.md` (this directory),<br/>
&nbsp; &nbsp; script at `Bin/500.verify-PR/502.fix-27-integration-test.sh`.

## Vendor-PR framing (for the eventual upstream submission)

Title: &nbsp; *Add 'Delete Revoked Certificates' option to Database Maintenance Worker*<br/>
&nbsp; &nbsp; (matches the title of fix request 27 in the operator's existing EE feature request).

*"Adds a new optional capability to the Database Maintenance Worker:<br/>
&nbsp; &nbsp; deletion of revoked certificate records filtered by revocation reason,<br/>
&nbsp; &nbsp; regardless of `expireDate`.<br/>
Pairs with the Single Active Certificate Constraint feature,<br/>
&nbsp; &nbsp; which auto-revokes superseded certificates on renewal.<br/>
Together they form a complete automated lifecycle<br/>
&nbsp; &nbsp; without revoked-record accumulation."*

Files in the PR diff: all entries from the table above — Layer A and Layer B.

The worker class ships in the PR because CE has no worker class at all<br/>
&nbsp; &nbsp; (see *Two adoption tracks*).

The PR description includes a note for the vendor's EE-side maintainers<br/>
&nbsp; &nbsp; identifying the Layer B subset to graft into their existing worker.

The PR body cross-references the operator's existing EE feature request<br/>
&nbsp; &nbsp; and mentions (politely) that the work is already done and tested.
