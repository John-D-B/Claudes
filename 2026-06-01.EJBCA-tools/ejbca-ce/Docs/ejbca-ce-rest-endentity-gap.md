# EJBCA CE — End Entity REST (a.k.a. "Management REST API") Is Enterprise-Only

**Author:** JohnB, with AI pair-programming support by Anthropic Claude
<br/>
**Date:** 2026-05-20

**Status:** Plan-breaking discovery during Phase 1, sub-step 1.4d. Vendor-<br/>
&nbsp; &nbsp; documented edition gate, not a bug.

**Summary:**<br/>
EJBCA-CE (Community Edition) ships the **Enrollment REST API** but not the **Management REST API**.

These End Entity REST endpoints — which **ELT** depends on for seven of ten endpoints —<br/>
&nbsp; &nbsp; fall under the Management REST API and are therefore unavailable in CE:
  - `/v1/endentity/*`
  - `/v2/endentity/*`

<br/>

## Vendor-documented edition gate

Community versus Enterprise<br/>
This URL documents the discrepency directly in the **Enrollment Protocols and APIs** matrix:

<https://www.ejbca.org/community-vs-enterprise>

Relevant rows:

| Feature | Community | Enterprise |
|---|---|---|
| SOAP API | ✓ | ✓ |
| **Enrollment REST API** | ✓ | ✓ |
| **Management REST API** | **✗** | **✓** |

The split, in plain terms:

**Enrollment REST API**<br/>
This covers the operations a **certificate consumer** needs:<br/>
&nbsp; &nbsp; enroll, get CA info, revoke a certificate by issuer+serial, check status.<br/>
CE ships this.<br/>

ELT uses these:<br/>
- `/v1/ca`
- `/v2/certificate/search`
- `/v2/certificate/count`
- `/v1/certificate/{issuer}/{serial}/revoke`

**Management REST API**<br/>
This covers operations an **administrator** performs against End Entities:<br/>
&nbsp; &nbsp; add, search, edit, delete, revoke, setstatus, list profiles.<br/>
CE does not ship this.<br/>
ELT uses seven of these endpoints.

<br/>

## What we confirmed:

The deployed `ejbca-rest-api.war` in `keyfactor/ejbca-ce:latest`<br/>
&nbsp; &nbsp; (version 9.3.7 Community) contains exactly five classes:

```
RestApiApplication.class
CaRestResourceSwagger.class                  → /v1/ca/*
CertificateRestResourceSwagger.class         → /v1/certificate/*
CertificateRestResourceV2Swagger.class       → /v2/certificate/*
SystemRestResourceSwagger.class              → /v1/system/*
```

There is no End Entity REST resource class in either the deployed WAR, or the open-source CE source tree:<br/>
`ejbca-ce/modules/ejbca-rest-api/`.

The admin GUI's protocol-toggle page advertises the protocol because the same GUI ships with both editions,<br/>
&nbsp; &nbsp; but enabling the toggle in CE has no effect — every request returns:
```
HTTP 404
{
 "error_code":    404,
 "error_message": "RESTEASY003210: Could not find resource for full path: …/v2/endentity/…"
 }
```

That UI/runtime mismatch is itself worth raising with the vendor — see "Process and downstream notes" at the bottom.

<br/>

## Endpoint inventory: ELT vs CE

This table lists **existing** EJBCA endpoints that ELT calls today; it is **not** a list of endpoints we propose to add.<br/>
The "shipped in CE?" column flags which calls work against CE versus require EE.

New endpoints  proposed for the upstream vendor are described here:<br/>
&nbsp; &nbsp; [elt/insights/CLAUDE-ejbca-fix-requests.md](../elt/insights/CLAUDE-ejbca-fix-requests.md)<br/>

Fix request 26 in particular adds a *certificate*-record delete, which is distinct from the existing endpoint:<br/>
&nbsp; &nbsp; `DELETE /v1/endentity/{name}`

| Endpoint ELT calls | Vendor category | Shipped in CE? |
|---|---|---|
| `POST /v1/endentity/search` | Management REST | **No** |
| `POST /v2/endentity/search` | Management REST | **No** |
| `DELETE /v1/endentity/{name}` | Management REST | **No** |
| `PUT /v1/endentity/{name}/revoke` | Management REST | **No** |
| `POST /v1/endentity/{name}/setstatus` | Management REST | **No** |
| `GET /v2/endentity/profiles/authorized` | Management REST | **No** |
| `GET /v2/endentity/profile/{name}` | Management REST | **No** |
| `POST /v2/certificate/search` | Enrollment REST | Yes |
| `GET /v2/certificate/count` | Enrollment REST | Yes |
| `PUT /v1/certificate/{issuer}/{serial}/revoke` | Enrollment REST | Yes |
| `GET /v1/ca` | Enrollment REST | Yes |

Seven of ten endpoints are in the Management REST API and absent from CE.

<br/>

## Implications for ELT

**Fix 26 (DELETE certificate)** and **Fix 27 (DBMS worker)** remain feasible in CE.<br/>
Both touch CE-shipped code:<br/>
&nbsp; &nbsp; `CertificateRestResource` &nbsp; &nbsp; &nbsp; &nbsp; (for fix 26's new endpoint)<br/>
&nbsp; &nbsp; `CertificateStoreSession` EJB &nbsp; (for fix 26's service layer)<br/>
&nbsp; &nbsp; `DatabaseMaintenanceWorker*` &nbsp; &nbsp; (for fix 27)<br/>

**Fix 20 / PR #129 remains valid:** &nbsp; &nbsp; EJBCA-Issuer for K8s cert-manager<br/>
This uses an Enrollment REST endpoint in CE:<br/>
&nbsp; &nbsp; `/v1/certificate/pkcs10enroll`

**cert-manager EJBCA-Issuer testing against CE still works.**<br/>
The issuer uses only Enrollment REST endpoints.

**ELT against CE is blocked by this gap.**

<br/>

## Paths forward

Five realistic work-around options were considered.<br/>
This one was chosen:

### Option C — Add an additive SOAP backend to ELT

**Critical framing:** this is **not a rewrite**.<br/>
Existing REST functionality against EE must remain byte-for-byte unchanged.

The work is to **add** a second backend that handles End Entity operations via the SOAP Web Service,<br/>
&nbsp; &nbsp; when REST isn't available.

EJBCA CE ships the SOAP Web Service (`ejbca-ws`) with full management coverage,<br/>
&nbsp; &nbsp; including end entity operations.

ELT becomes hybrid:<br/>
&nbsp; &nbsp; REST for Certificate / CA operations (already working on both CE and EE),<br/>
&nbsp; &nbsp; SOAP for End Entity operations when targeting CE.

**Backend selection** (three layers, priority order):

- CLI flag:<br/>
&nbsp; &nbsp; `-z` / `--zeep` forces SOAP for End Entity operations<br/>
&nbsp; &nbsp; `--rest` forces today's REST-only behavior

- Bash Environment variable:<br/>
&nbsp; &nbsp; `$ export ELT_BACKEND=rest|soap|auto`

- Auto-detect (default):<br/>
&nbsp; &nbsp; When ELT runs, probe a Management REST endpoint:<br/>
&nbsp; &nbsp; &nbsp; &nbsp; `GET /v2/endentity/profiles/authorized`<br/>
&nbsp; &nbsp; HTTP 404 → CE → switch  to SOAP backend.<br/>
&nbsp; &nbsp; HTTP 200 → EE → stay on REST default.<br/>
&nbsp; &nbsp; Cache for session lifetime.

### This SOAP client implementations was chosen:

#### Option C.1 — Direct SOAP from Python via `zeep`

- `zeep` is the mature modern Python SOAP library.<br/>
- It adds one dependency to `requirements.txt`.<br/>
- ELT remains a single self-contained Python tool.<br/>
- mTLS auth uses the same client cert/key already in place; no new auth surface.

Cost: medium:<br/>
- Implement an `EjbcaSoapBackend` class with the seven End Entity operations
- Wire dispatch in `EjbcaClient`
- Add the flag/env/ auto-detect logic.

Pro:<br/>
- Clean Python-only solution.
- Consistent with ELT's character.

Con:<br/>
- SOAP wrangling has real complexity, even with a good library:<br/>
&nbsp; &nbsp; WSDL, XML namespaces, type mapping

<br/>

## What the SDKs do (and don't) help with

These Python SDKs were checked and turn out not to bridge this gap,<br/>
&nbsp; &nbsp; and **zeep** was chosen instead.

### ejbca-python-client-sdk
&nbsp; &nbsp; <https://github.com/Keyfactor/ejbca-python-client-sdk><br/>

This is a thin Python wrapper around EJBCA's REST API, auto-generated from the OpenAPI spec.<br/>
It calls the same endpoints we just verified.

The CE End Entity gap propagates straight through it — having SDK stubs for End Entity methods<br/>
&nbsp; &nbsp; doesn't help, when the server has no implementation to receive the calls.

The SDK could still be useful for the Certificate / CA endpoints that ELT uses (modest cleanliness win),<br/>
&nbsp; &nbsp; but it doesn't solve the gap.


### keyfactor-python-client-sdk
&nbsp; &nbsp; <https://github.com/Keyfactor/keyfactor-python-client-sdk><br/>

This SDK targets a different product:<br/>
&nbsp; &nbsp; **Keyfactor Command**, a commercial certificate-lifecycle-management platform, not **EJBCA** itself.<br/>
&nbsp; &nbsp; Not applicable.


### EJBCA CLI \& Client Toolbox
&nbsp; &nbsp; <https://docs.keyfactor.com/ejbca/latest/command-line-interfaces><br/>
&nbsp; &nbsp; <https://docs.keyfactor.com/ejbca/latest/ejbca-client-toolbox><br/>

These *do* fully bridge the gap functionally.<br/>
However, these are separate scripts and apps run as spawned processes, not Python libraries.<br/>
This makes ELT integration and distribution more complicated.

<br/>

## Process and downstream notes

Items worth following up separately:

The CE Docker image (`keyfactor/ejbca-ce`) leaves the WildFly truststore empty after the simple-TLS bootstrap,<br/>
&nbsp; &nbsp; so any client cert fails validation and WildFly drops the connection silently.

This trips up anyone trying mTLS to a fresh CE container.

This is documented and worked around in step 1.4c of our roadmap;<br/>
&nbsp; &nbsp; arguably a bug or at least a vendor documentation gap.
