# EJBCA CE — Task 3.7: Fix 26 Integration Test Plan

**Author:** JohnB, with AI pair-programming support by Anthropic Claude
<br/>
**Date:** 2026-05-22

**Purpose:**<br/>
Validate the new REST endpoint added by Fix 26:<br/>
&nbsp; &nbsp; `DELETE /v1/certificate/{issuer_dn}/{cert_serial_number}`

The plan covers the happy path (enroll → revoke → delete → confirm gone)<br/>
&nbsp; &nbsp; plus the documented error cases (404 unknown serial, 409 not-yet-revoked).

**Note on the published script:**<br/>
This plan describes the self-provision test cases (T1–T9).<br/>
The published script (`Bin/500.verify-PR/501.fix-26-integration-test.sh`, v2.5.0+)<br/>
&nbsp; &nbsp; additionally implements **BYOC mode** ("Bring Your Own Certificates"),<br/>
&nbsp; &nbsp; which runs the same delete-and-verify assertions against existing certificates.<br/>
BYOC mode is described in the Fix-26 PR description and demonstrated in `../DEMO.md` Part 5.

## Prerequisites

The test is **self-contained**: it does not consume any pre-existing certificate records.

It does require the locally-built `ejbca-ce:local-fixes` image,<br/>
&nbsp; &nbsp; because the new DELETE endpoint only exists in the Fix-26 code.

The two prerequisites are therefore:

- **Image built:**<br/>
The container image is built locally from the modified source tree<br/>
&nbsp; &nbsp; (`Bin/230.rebuild/231.build-local-image.sh`).

- **Stack swapped:**<br/>
The running CE stack uses `ejbca-ce:local-fixes` rather than the upstream<br/>
&nbsp; &nbsp; `keyfactor/ejbca-ce` (`Bin/230.rebuild/232.swap-stack-image.sh`).

The smoke test (`Bin/900.probes/901.smoke-test.sh`) covers stack restart<br/>
&nbsp; &nbsp; procedure; nothing new is needed in that area.

## Test design

The test is a single shell script:<br/>
&nbsp; &nbsp; `Bin/500.verify-PR/501.fix-26-integration-test.sh`

It follows the same PASS/FAIL/REVIEW output pattern as the smoke test,<br/>
&nbsp; &nbsp; so its output is grep-friendly and consistent with the rest of the project.

Two test certificates are enrolled fresh at the start of each run,<br/>
&nbsp; &nbsp; each with a per-run-unique end-entity name (timestamp-suffixed).<br/>
One drives the happy path through to deletion.<br/>
The other stays unrevoked and exercises the 409 branch.

Enrollment goes through ELT's SOAP backend,<br/>
&nbsp; &nbsp; matching how the rest of the project produces test certificates against the CE stack.<br/>
ELT's REST path is not used because CE doesn't expose the End Entity REST API<br/>
&nbsp; &nbsp; (see `ejbca-ce-rest-endentity-gap.md` in this directory).

The REST endpoints under test (`revocationstatus`, `revoke`, the new `DELETE`)<br/>
&nbsp; &nbsp; are exercised directly via `curl`, using the `ce-eltadmin.{crt,key}`<br/>
&nbsp; &nbsp; client certificate for mTLS — the same credential the smoke test uses.

## Test cases

| ID | What it checks | Expected |
|---|---|---|
| T1 | Enroll fresh test EE `delete-happy-<ts>`, get a cert | 0 exit, p12 produced |
| T2 | `GET .../revocationstatus` for the happy cert | 200, `revoked=false` |
| T3 | `PUT .../revoke?reason=SUPERSEDED` | 200, `revoked=true` |
| T4 | `GET .../revocationstatus` again | 200, `revoked=true`, reason `SUPERSEDED` |
| T5 | `DELETE .../{issuer_dn}/{serial}` — **the new endpoint** | 204 No Content |
| T6 | `GET .../revocationstatus` after delete | 404 Not Found |
| T7 | `DELETE` against a bogus serial number | 404 Not Found |
| T8 | Enroll fresh test EE `delete-409-<ts>`, no revoke | 0 exit, p12 produced |
| T9 | `DELETE` against the unrevoked cert from T8 | 409 Conflict |

The two negative tests (T7, T9) are what distinguish this from "did the endpoint compile".<br/>
They confirm the actual error-handling shape promised by the OpenAPI annotations.

## Test data cleanup

The test creates two fresh end entities per run,<br/>
&nbsp; &nbsp; named with a per-run timestamp (e.g. `delete-happy-20260522-143015`).

The happy-path one is deleted as part of the test itself.<br/>
The 409 one is left revoked-but-undeleted in the database after the run,<br/>
&nbsp; &nbsp; ready to be swept by a subsequent worker run or cleaned up manually.

This leaves a small residue across runs.<br/>
That is acceptable for a DEV stack, and parallels how the smoke tests behave.

## Running the test

```sh
$ Bin/500.verify-PR/501.fix-26-integration-test.sh
```

Exits 0 if all PASS, 1 otherwise.<br/>
A summary block at the end lists every test case with its status,<br/>
&nbsp; &nbsp; the same way the smoke test does.

If the stack is still on the upstream image, T5 returns 404<br/>
&nbsp; &nbsp; (the endpoint doesn't exist yet) and the script fails at that step —<br/>
&nbsp; &nbsp; confirming the build-and-swap prerequisites have to happen first.

## What the test does **not** cover

This is a black-box validation against the running stack.<br/>
It doesn't measure coverage of the Java code paths in<br/>
&nbsp; &nbsp; `CertificateRestResource.java` or `deleteRevokedCertificate` in<br/>
&nbsp; &nbsp; `CertificateStoreSessionBean.java`.<br/>
A full unit/system test would belong in the vendor's Java test framework<br/>
&nbsp; &nbsp; alongside the eventual upstream PR.

The 403 authorization branch is also out of scope here.<br/>
Exercising it would require a second admin role configured with no CA access,<br/>
&nbsp; &nbsp; which is more setup than this prototype warrants.
