# EJBCA CE — Task 3.6: REST DELETE Endpoint Design (fix 26)

**Author:** JohnB, with AI pair-programming support by Anthropic Claude
<br/>
**Date:** 2026-06-11

> <br/>**Design:**<br/>
> Fix 26 is small, additive, and builds on infrastructure designed for Fix 27:<br/>
> - Development roadmap<br/>
> - Integration-test plan<br/>
> - PR description<br/>
> 
> <br/>

<br/>

**Purpose:**<br/>
Add an on-demand deletion endpoint to the EJBCA REST API:<br/>
&nbsp; &nbsp; `DELETE /v1/certificate/{issuer_dn}/{certificate_serial_number}`

The endpoint permanently deletes the database row for a certificate<br/>
&nbsp; &nbsp; that is **already in REVOKED status**.

## The problem

Fix 27 (the Database Maintenance Worker's *Delete Revoked Certificates* mode)<br/>
&nbsp; &nbsp; handles steady-state bulk cleanup on a schedule.

Schedule-based cleanup does not cover three real operational cases:

- **Automation cleanup and garbage collection:**<br/>
e.g. a Kubernetes platform team running its own `kubectl`-style flow<br/>
&nbsp; &nbsp; that revokes-and-deletes in one atomic operation,<br/>
&nbsp; &nbsp; rather than relying on EJBCA's schedule.

- **Test-harness automation:**<br/>
The worker's batch semantics aren't ideal for assertion-driven tests;<br/>
&nbsp; &nbsp; a per-certificate REST endpoint is.

- **Operator response to a specific incident:**<br/>
e.g. a misissued cert that's been revoked and now needs to disappear from the database<br/>
&nbsp; &nbsp; without waiting for the next worker run.

Fix 26 is part (b) of customer ticket **#172467** / engineering reference **ECA-15056**:<br/>
&nbsp; &nbsp; *"(a) Handles bulk steady-state cleanup. (b) Handles operator-action and customer tooling.<br/>
&nbsp; &nbsp; We need both."*

## Design at a glance

- **Endpoint:**<br/>
`DELETE /v1/certificate/{issuer_dn}/{certificate_serial_number}`

- **Path shape:**<br/>
Identical to this existing revoke endpoint:<br/>
&nbsp; &nbsp; &nbsp; &nbsp; (`PUT .../{issuer_dn}/{certificate_serial_number}/revoke`),<br/>
&nbsp; &nbsp; Operators familiar with revoke will find this delete in a comparable place.

- **Precondition:**<br/>
The certificate must already be in REVOKED status.

- **Authorization:**<br/>
Per-CA, same conceptual level as REVOKE (see *Design decisions* below).

- **Footprint:**<br/>
Two files, +95 lines, all additive.

| Response | Meaning |
|---|---|
| `204 No Content` | Row deleted. |
| `400 Bad Request` | Malformed serial number (with explanatory message). |
| `403 Forbidden` | Caller lacks CA access for the issuing CA. |
| `404 Not Found` | No such certificate (or it vanished mid-operation). |
| `409 Conflict` | Certificate is not revoked; body points the caller at the revoke endpoint. |

## Operation flow

Implementation in `CertificateRestResource.java`, new `deleteCertificate(...)` method:

1. **Parse serial:**<br/>
`StringTools.getBigIntegerFromHexString(serialNumber)` —<br/>
&nbsp; &nbsp; the same helper used by the existing `revokeCertificate(...)`.<br/>
Returns **400** with an explanatory message on malformed input.

2. **Authorize:**<br/>
`authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caId)`<br/>
&nbsp; &nbsp; where `caId = issuerDN.hashCode()`.<br/>
Returns **403** if the caller lacks CA access.

3. **Locate:**<br/>
`certificateStoreSession.findCertificateByIssuerAndSerno(...)`,<br/>
&nbsp; &nbsp; then `getCertificateInfo(fingerprint)`.<br/>
Returns **404** if either returns null.<br/>
The two-step lookup handles the race where the row vanishes between calls:<br/>
&nbsp; &nbsp; treated as 404 (not 500), matching how `revokeCertificate(...)` handles the same race.

4. **Precondition check:**<br/>
Reject **409 Conflict** if the certificate is not in `CERT_REVOKED` status.<br/>
The conflict body explains the required workflow:<br/>
&nbsp; &nbsp; revoke first via `PUT .../{issuer_dn}/{certificate_serial_number}/revoke`.

5. **Delete:**<br/>
`certificateStoreSession.deleteRevokedCertificate(...)` — the EJB primitive added by Fix 27.<br/>
Emits the same `EventTypes.CERT_CLEANUP` audit-log entry as the worker.<br/>
Returns **204** on success.

The OpenAPI surface lives in `CertificateRestResourceSwagger.java`:<br/>
&nbsp; &nbsp; `@DELETE` JAX-RS annotation, the path template,<br/>
&nbsp; &nbsp; an `@Operation` summary, and the four documented `@ApiResponse` codes (204 / 403 / 404 / 409).

It delegates straight through to the resource implementation.

## Dependency on Fix 27

Fix 26 deliberately reuses Fix 27's infrastructure rather than duplicating it:

- **The deletion primitive:**<br/>
The per-row `deleteRevokedCertificate(...)` EJB call is Fix 27's contribution;<br/>
&nbsp; &nbsp; Fix 26 adds no new database-layer code.

- **The audit trail:**<br/>
Both paths emit `EventTypes.CERT_CLEANUP` with the `store.deletedrevokedcert` i18n key,<br/>
&nbsp; &nbsp; so a deletion looks the same in the audit log<br/>
&nbsp; &nbsp; whether the worker or an operator performed it.

- **Branch lineage:**<br/>
The Fix-26 branch is cut from the Fix-27 branch.<br/>
The Fix-27 PR must land first (or together).

This is why the two PRs form a pair:<br/>
&nbsp; &nbsp; Fix 27 provides the safe deletion machinery and the scheduled bulk path;<br/>
&nbsp; &nbsp; Fix 26 exposes the same machinery as a single-certificate operator action.

## Design decisions and alternatives

### Decision 1: Authorization rule: `StandardRules.CAACCESS`

Chosen: the caller must have CA access for the issuing CA.<br/>
Rationale: DELETE here is conceptually parallel to REVOKE, which uses equivalent gating.

Every REST operation is already authenticated via mTLS and authorized via EJBCA roles;<br/>
&nbsp; &nbsp; `DELETE` is no more privileged than `REVOKE`.

Alternatives considered:

- **(a) `CAEDIT` (more restrictive):**<br/>
the caller must be able to *edit* the CA, not just see its certificates.<br/>
Probably overkill for a per-certificate operation.

- **(b) A new fine-grained `CERTIFICATE_DELETE` rule:**<br/>
cleaner long-term, but introduces a new permission boundary that doesn't exist elsewhere.<br/>
Adoption risk.

- **(c) Super-admin only:**<br/>
too restrictive — defeats the "operator-action" half of the motivation.

This is flagged as a reviewer-attention item in the PR.

### Decision 2: CA-ID derivation: `issuerDN.hashCode()`

The audit-log call uses `String.valueOf(certInfo.getIssuerDN().hashCode())` as the CA ID string.<br/>
Rationale: matches the pattern in the existing `deleteExpiredCertificate(...)` directly above it.

Alternative: `CaSessionLocal.getCAIdFromDN(...)` or equivalent.<br/>
Also flagged as a reviewer-attention item.

### Decision 3: Revoked-only precondition (the 409 guard)

Deletion is refused unless the certificate is already revoked.

This enforces a two-step workflow (revoke, then delete) for active certificates,<br/>
&nbsp; &nbsp; preventing a single privileged call from silently removing a live certificate.

The revocation step keeps the CRL/OCSP story consistent:<br/>
&nbsp; &nbsp; the certificate is invalidated before its record disappears.

### Open question: hard delete vs soft delete ?

The implementation performs a hard delete (the row is removed).<br/>

Alternative: a soft-delete variant (flagging rather than removing)<br/>
Flagged as a reviewer-attention item.

## Backward compatibility

Pure addition:

- Existing endpoints: no shape, path, or behaviour changes.
- Existing class signatures: unchanged.
- The `DELETE` verb is new at this path — no method/verb collision.
- The two new `@EJB` injections on `CertificateRestResource`<br/>
&nbsp; &nbsp; (`CertificateStoreSessionLocal`, `AuthorizationSessionLocal`) are class-local.

## Validation

Test plan: `ejbca-ce-task-3.7-fix-26-test-plan.md` (this directory).<br/>
Test script: `Bin/500.verify-PR/501.fix-26-integration-test.sh`.

Recorded results:

- **Self-provision mode:**<br/>
  9/9 PASS (T1–T9) against EJBCA CE 9.3.7 + both PR fixes.

- **BYOC mode**<br/>
("Bring Your Own Certificates"):<br/>
This is a 174-certificate real-world corpus:<br/>
&nbsp; &nbsp; — 173 revoked certificates deleted and verified gone<br/>
&nbsp; &nbsp; — 1 active certificate correctly refused with 409

The end-to-end story (including how the corpus was produced) is in `../DEMO.md`.

## References

- **Customer ticket #172467** (Keyfactor support; accepted by engineering as ECA-15056)<br/>
<https://support.keyfactor.com/hc/en-us/requests/172467>

- **Fix-27 design doc** — the worker and the shared deletion primitive:<br/>
`ejbca-ce-task-3.4-dbms-worker-design.md` (this directory)

- **Published tool bundle** — stack, scripts, and tests:<br/>
<https://github.com/John-D-B/Claudes/tree/main/2026-06-01.EJBCA-tools>
