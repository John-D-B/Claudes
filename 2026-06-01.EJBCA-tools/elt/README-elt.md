# X.509 Certificate Lifecycle

**EJBCA · Kubernetes cert-manager · ejbca-lifecycle-tool.py**
<br/>
**Author:** John Buehrer (JohnB), with AI pair-programming support by Anthropic Claude
<br/>
**Date:** 2026-06-01

An X.509 certificate has a defined lifecycle: it is requested, issued, deployed, renewed before expiry, and eventually revoked or expired. In a Kubernetes environment, cert-manager automates most of this lifecycle, with EJBCA acting as the Certificate Authority. The table below summarises each step, how it is implemented, and where gaps exist.

---

## Lifecycle Steps

<table>
<thead>
<tr>
  <th style="white-space:nowrap">Step</th>
  <th>Standard X.509</th>
  <th>EJBCA + cert-manager</th>
  <th>Gaps / Notes</th>
</tr>
</thead>
<tbody>
<tr>
  <td style="white-space:nowrap"><strong>1. Request</strong></td>
  <td>Application generates a key pair and submits a CSR.</td>
  <td>cert-manager generates the key pair and submits a CSR to EJBCA via the REST API.</td>
  <td>Works well.</td>
</tr>
<tr>
  <td style="white-space:nowrap"><strong>2. Issuance</strong></td>
  <td>CA validates the CSR and signs the certificate.</td>
  <td>EJBCA validates, signs, and returns the certificate. The End Entity record is created or reused.</td>
  <td>Works well.</td>
</tr>
<tr>
  <td style="white-space:nowrap"><strong>3. Deployment</strong></td>
  <td>Certificate is installed and used by the application.</td>
  <td>cert-manager stores the certificate as a Kubernetes Secret, automatically available to pods.</td>
  <td>Works well.</td>
</tr>
<tr>
  <td style="white-space:nowrap"><strong>4. Renewal</strong></td>
  <td>Before expiry, a new certificate is requested to replace the current one.</td>
  <td>cert-manager triggers renewal based on a <code>renewBefore</code> threshold. It submits a fresh CSR — this is a new issuance, not a true renewal in EJBCA terms.</td>
  <td>cert-manager ignores the EJBCA certificate profile validity; the requested duration is not passed to EJBCA. ¹</td>
</tr>
<tr>
  <td style="white-space:nowrap"><strong>5. Revocation</strong></td>
  <td>Certificate is invalidated before expiry (compromise, decommission, etc.).</td>
  <td>EJBCA supports revocation via REST API. With Single Active Certificate Constraint enabled, the previous certificate is auto-revoked on each renewal.</td>
  <td>Without the constraint, old certificates accumulate and must be cleaned up manually.</td>
</tr>
<tr>
  <td style="white-space:nowrap"><strong>6. Expiry &amp; Cleanup</strong></td>
  <td>Expired certificates are removed from active use and eventually purged from records.</td>
  <td>EJBCA's Database Maintenance Service purges expired certificate records on a schedule.</td>
  <td>Only expired records are purged — revoked-but-unexpired records accumulate until their <code>notAfter</code> date. ²</td>
</tr>
</tbody>
</table>

---

## Known Gaps

¹ **cert-manager duration ignored by EJBCA** — The requested certificate duration is not passed to EJBCA; the Certificate Profile validity always takes precedence. ([Keyfactor issue #128]( https://github.com/Keyfactor/ejbca-cert-manager-issuer/issues/128 ); fix in review: [PR #129]( https://github.com/Keyfactor/ejbca-cert-manager-issuer/pull/129 ))

² **Revoked records not purged until expiry** — EJBCA's Database Maintenance Service only deletes *expired* certificate records. Revoked certificates with a long nominal lifetime (e.g. 2 years) remain in the database until they expire, even if revoked shortly after issuance. Short-lived certificate profiles (e.g. 47 days) mitigate this: revoked records are purged within days of expiry.

---

## The ejbca-lifecycle-tool.py Tool

`ejbca-lifecycle-tool.py` is a Python command-line tool that communicates securely with EJBCA using its REST API and mTLS client certificate authentication — the same access control mechanism used by cert-manager itself. No direct database access or admin shell is required.

The key design principle is that the tool is organised around EJBCA **End Entities (EEs)** as its primary unit of work, rather than individual X.509 certificates. This mirrors how EJBCA itself organises certificate data: each End Entity is a named identity that owns one or more certificates over its lifetime. Understanding this EE-centric view is essential for making sense of certificate accumulation, renewal behaviour, and cleanup in EJBCA — it is a different mental model from the certificate-centric view common in traditional PKI tooling.

In the course of development and testing, the tool has also surfaced several gaps and bugs in the EJBCA / cert-manager integration — including the certificate duration issue noted above — which are documented for follow-up with the vendor.

---

## How ejbca-lifecycle-tool.py (`elt`) Helps

| Command | What it shows or does |
|---------|----------------------|
| `elt --help` | Shows all script options and actions. Run this first. |
| `elt ping` | Verifies REST API connectivity to EJBCA (with a 10-second timeout, to detect firewall-blocked connections quickly). Run this second, with connection parameters or with env vars. |
| `elt list2` | Shows all End Entity Profiles with their associated Certificate Profiles, CAs, and numeric IDs — useful for auditing configuration. |
| `elt list4` | Shows every End Entity with its certificates (active and revoked), serial numbers, validity dates, and CN — the full picture per EE. |
| `elt count` | Certificate count summary: global totals plus a per-EE breakdown of active vs. revoked, sortable by any column. |
| `elt count -k8s-compare` | Cross-references EJBCA End Entities against live Kubernetes cert-manager certificates, identifying orphans (EEs no longer backed by a cert-manager resource). |
| `elt cleanup -keep-newest 1` | Revokes all but the newest certificate per End Entity — cleans up accumulation from renewals. Dry-run by default; add `-confirm` to execute. |

For recommended EJBCA configuration settings for use with cert-manager (CA, Certificate Profile, End Entity Profile), run: **`elt --hints`**

---

## Backends: REST and SOAP (new in v4.0.0)

From v4.0.0, ELT supports two backends for its End Entity operations and selects between them automatically. Existing REST behaviour against **EJBCA Enterprise** is unchanged; users on EE don't need to change anything.

The new SOAP backend is for users targeting **EJBCA Community Edition**. CE does not ship the "Management REST API" (per Keyfactor's [Community vs Enterprise comparison]( https://www.ejbca.org/community-vs-enterprise/ )), so the End Entity REST endpoints ELT relies on are unavailable. ELT now uses EJBCA's **SOAP Web Service** instead, which CE does ship. Certificate-record endpoints (`/v1/certificate/*` and `/v2/certificate/*`) work the same on both editions and remain on REST.

### Selecting a backend

Three layers, in priority order:

1. **CLI flag** — `-z` or `--zeep` forces SOAP; `--rest` forces REST.
2. **Environment variable** — `ELT_BACKEND=rest|soap|auto`.
3. **Auto-detect (default)** — ELT probes a Management REST endpoint on startup. HTTP 404 → SOAP (CE detected). HTTP 200 → REST (EE).

The same mTLS client certificate and key work for both backends; no additional configuration is needed.

### SOAP backend dependency

The SOAP backend requires the **zeep** library, listed in `requirements.txt` as an optional dependency. REST-only deployments don't need it. zeep is imported lazily — only when the SOAP backend is actually instantiated — so ELT starts cleanly even without it.

```bash
pip install zeep
```

### Functional coverage

The SOAP backend covers the same six logical End Entity operations as REST: search, revoke, delete, get, get profile, and list authorized profiles. The mapping is one-to-one with a few EJBCA-specific adaptations:

- `DELETE /v1/endentity/{name}` maps to SOAP `revokeUser` with `deleteUser=True` (revoke and delete in one call — EJBCA's traditional pattern).
- Profile lookups by name resolve via a cached name → ID map (SOAP `getProfile` takes the profile ID, REST takes the name).
- Multi-criterion search applies the first criterion server-side via SOAP `findUser`; any additional criteria are post-filtered client-side. Single-criterion search (the common ELT case) goes through with no overhead.

---

## A Real-World Use Case

This tool was developed in the context of a shared PKI service: EJBCA admins acting as a service provider to internal corporate customers running Red Hat OpenShift (RHOS) — a large Kubernetes platform requiring automated TLS certificate management. The customers use Kubernetes cert-manager with the EJBCA issuer, but have limited expertise (or interest) in the EJBCA backend. On the EJBCA side, the goal is to offer a clean service — but in practice, that requires understanding how cert-manager and the Keyfactor issuer work, and being prepared to diagnose and solve integration issues.

A central tension in this setup is certificate lifetime. The security team requires TLS server certificates with a standard maximum validity of **2 years**, per corporate policy. Meanwhile, RHOS customer teams want variable lifespans — sometimes as short as **one hour** for testing. cert-manager handles this transparently from the Kubernetes side, but the consequences inside EJBCA are significant.

The core problem is a paradigm mismatch. When cert-manager "renews" a certificate, it does not extend the existing one — it issues a brand-new certificate (new key, new serial, new CSR) under the same End Entity, and simply marks the old certificate as revoked. But that revoked certificate still carries its original 2-year expiry date. It is not "revoked" in the traditional sense of being compromised or decommissioned; it is merely an artifact of cert-manager's renewal cycle. In a high-frequency renewal environment (e.g. hourly test certificates), this produces thousands of such obsolete records in EJBCA — all formally valid, unexpired, and revoked — which accumulate until they naturally expire two years later.

**ejbca-lifecycle-tool.py** is vital for making this situation visible. Its End Entity-centric view, combined with per-EE certificate counts and active/revoked breakdowns, allows the scale of accumulation to be measured precisely. At the time of writing, this environment contains **thousands of such obsolete certificate records**. The tool is also the operational basis for automated remediation — identifying which End Entities carry excess revoked certificates and revoking the backlog down to a manageable state, as quickly as EJBCA permits.

A short-term mitigation is to adopt **short-lived certificate profiles (e.g. 47 days)** for cert-manager-managed End Entities where appropriate. At that validity, revoked records expire and are purged by EJBCA's Database Maintenance Service within weeks, bounding accumulation automatically. This will reduce the current backlog as existing long-lived certs age out, though it will not eliminate it immediately. That said, not all internal corporate customers run public web services — in some cases a longer certificate lifetime remains appropriate, and the 47-day profile should not be applied universally.

A further short-term measure is to engage **Keyfactor** to provide a facility for more targeted purging of obsolete records — either through a new Database Maintenance Service option, or preferably a new **REST API endpoint** (e.g. `DELETE /v1/certificate/{issuer}/{serial}`) which ejbca-lifecycle-tool.py could invoke directly, using permissions already within the RA Administrator role template. Any such facility would also need to address OCSP and CRL database cleanup to maintain PKI consistency.

The most targeted near-term solution would be implementing the **pending Keyfactor issuer fix** ([issue #128]( https://github.com/Keyfactor/ejbca-cert-manager-issuer/issues/128 )), so that RHOS customer teams can request their desired certificate duration in their Kubernetes YAML, subject to the maximum lifetime enforced by the EJBCA Certificate Profile. This avoids both the accumulation problem and "End Entity profile explosion" — a separate EJBCA profile for every desired lifetime across a large multi-tenant environment.

Regardless of which mitigations are adopted, **ejbca-lifecycle-tool.py** will remain necessary for ongoing monitoring. Excess certificates consume EJBCA database resources and may affect licensing costs. The tool provides visibility to detect accumulation, identify orphans, and intervene before gaps or errant states go unnoticed.

---

## Appendix: elt --hints Output

The following is the verbatim output of **`elt --hints`**, which gives recommended EJBCA configuration settings for use with cert-manager. Run this command directly for the most up-to-date version.

```
bash$  alias elt="ejbca-lifecycle-tool.py"
bash$  elt --hints

ejbca-lifecycle-tool.py v3.4.0 — Configuration Hints

Here are my EJBCA configuration recommendations for optimal K8s cert-manager
lifecycle management. These settings minimize certificate accumulation,
enable automated cleanup, and align with industry best practices.
Tested with EJBCA Enterprise / Software Appliance, versions 9.3.3 - 9.4.2.

Tip: To see the associations of EE Profile, Cert Profile, and CA:
  $ ejbca-lifecycle-tool.py list2

CA Configuration
  - only for the "Issuing CA" referenced by the End Entity Profile.
  Enforce unique public keys: unchecked (avoid obscure errors and DB indexes)
  Enforce unique DN:          unchecked (same CN reused across renewals)
  Finish User:                checked (password not blanked for User Generated tokens)

Certificate Profile
  - only for the "Leaf certificate profile" referenced by the End Entity Profile.
  Type:                       End Entity
  Validity:                   47 days (short-lived, auto-renewed by cert-manager)
  Allow Validity Override:    checked (needed once the cert-manager issuer
                                supports passing requested validity to EJBCA)
  Single Active Cert:         checked (auto-revokes previous cert on renewal)

End Entity Profile
  - only for the "End Entity profiles" used by K8s cert-manager enrollments
  Username:                   Auto-generated: checked
                                (EJBCA assigns unique username; cert-manager
                                issuer may override via endEntityName)
  Password:                   Required: unchecked, Auto-generated: unchecked
                                (avoid credential mismatches between admins)
  Batch generation:           checked (allows automated re-enrollment for renewals,
                                avoiding "No password in request" error 400)
  Number of allowed requests: leave "Use" unchecked (unlimited re-enrollment)
  Default Token:              User Generated (cert-manager generates keys)
  Available Tokens:           all can be selected (supports RA Web exports)

  Note on "Allow Renewal Before Expiration": leave it unchecked.
  - This EJBCA feature allows re-enrollment while the EE is in GENERATED status.
  - But cert-manager does NOT use this mechanism.
  - The PKCS10 Enroll endpoint resets the EE to NEW status on each request,
    so it bypasses the GENERATED-status check entirely.
  - cert-manager "renewal" is really a fresh enrollment that reuses the EE username:
    new key, new serial, new CSR.

Role & Access Rules
  Role template:              RA Administrators
  Additional rules:           /system_functionality/view_systemconfiguration/
                                (needed for 'elt count' global totals)
  REST protocol:              REST Certificate Management must be enabled
  Authorized CAs:             select relevant CAs
  Authorized EE Profiles:     select relevant profiles
  Trusted CA list:            add the CA of your access certificate

Database Maintenance Service (Enterprise)
  Name:                       DBMS Certificate Reaper
  CAs to Check:               all CAs
  Delay After Expiration:     minimum allowed (DEV: 1 day, PROD: per compliance)
  Delete Expired Certs:       true
  Delete Expired CRLs:        true
  Entries per run:            1000-5000 (increase for large backlogs)
  Description:                Purge expired/revoked cert records and old CRLs

Why 47-Day Certificates?
  - CA/B Forum and Apple/Google converging on short TLS lifetimes
  - cert-manager handles renewals automatically (invisible to apps)
  - Revoked/expired certs purged by Database Maintenance in weeks, not years
  - Accumulation bounded: ~47 active certs max per EE (vs ~1095 for 3-year)
  - Reduced blast radius: compromised cert valid for weeks, not years

Known Gotchas
  - cert-manager "duration" field is ignored by EJBCA — cert lifetime
    is always set by the Certificate Profile validity, not the K8s YAML.
    Set renewBefore relative to the actual EJBCA-issued validity.
    ( https://github.com/Keyfactor/ejbca-cert-manager-issuer/issues/128 )

  - Single Active Cert may produce a duplicate cert (same NotBefore) on
    first renewal after config change — likely a one-time race condition

  - EE usernames are globally unique — collision risk in multi-tenant
    (consider deterministic hash for endEntityName)

  - Revoked certs with long remaining validity: ghost records persist
    until original expiry + delay (reason to use short-lived certs)

  - Always revoke before deleting EE (else: active ghost cert, no CRL entry)

  - EE-level revoke API may return 500 for EJBCA-generated keys
    (workaround: per-cert revoke via 'elt cleanup -keep-newest 0')
```
