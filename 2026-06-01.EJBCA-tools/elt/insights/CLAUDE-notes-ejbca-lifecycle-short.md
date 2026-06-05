# EJBCA Certificate Lifecycle with Kubernetes cert-manager

**ejbca-lifecycle-tool.py** · Findings and configuration guide  
*John Buehrer · March 2026*

---

## The Tool: ejbca-lifecycle-tool.py

`ejbca-lifecycle-tool.py` (`elt`) is a Python command-line tool for managing and auditing EJBCA certificate lifecycle in environments that use Kubernetes cert-manager. It communicates with EJBCA exclusively via the REST API using mTLS client certificate authentication — the same access control mechanism used by cert-manager itself. No direct database access, admin shell, or EJBCA GUI access is required.

The tool is organised around EJBCA **End Entities (EEs)** as its primary unit of work, rather than individual X.509 certificates. This mirrors how EJBCA itself organises certificate data: each End Entity is a named identity that owns one or more certificates over its lifetime. Understanding this EE-centric view is essential for making sense of certificate accumulation, renewal behaviour, and cleanup.

Key capabilities:

| Command | What it does |
|---------|-------------|
| `elt ping` | Verifies REST API connectivity (10-second timeout) |
| `elt list2` | Lists all EE Profiles with associated Cert Profiles, CAs, and numeric IDs |
| `elt list3` | Per-EE certificate count summary (active / revoked) |
| `elt list4` | Full per-EE certificate tables with serials, validity dates, and CN |
| `elt count` | Global totals plus per-EE active/revoked breakdown |
| `elt count -k8s-compare` | Cross-references EJBCA EEs against live cert-manager certificates |
| `elt count -ghosts` | Detects ghost EE usernames (cert records outliving their deleted EE) |
| `elt cleanup -keep-newest 1` | Revokes all but the newest cert per EE (dry-run by default) |
| `elt cleanup --delete-ee` | Revokes all certs and deletes the End Entity record |
| `elt --hints` | Prints recommended EJBCA configuration for cert-manager integration |

The tool has also surfaced several non-obvious behaviours and gaps in the EJBCA / cert-manager integration, documented below.

---

## 1. "Expire" vs "Revoke" — a Common Misconception

**Q: Can you just expire an old certificate instead of revoking it?**

No. Expiration is passive — it occurs when `notAfter` arrives. There is no API call to accelerate it. If a certificate is valid until 2028 and you want it invalid now, revocation is the only mechanism.

This is a very common source of confusion. The mental model mismatch is real: "renew" intuitively suggests a regular, expected lifecycle event (like renewing a driving licence), but in PKI the old certificate does not go away — it lingers until its natural expiration. The only way to invalidate it early is revocation, which carries the connotation of an emergency or security incident.

**The practical reality for cert-manager + short-lived TLS certs:**

- cert-manager creates new keys, a new CSR, and a new serial on each renewal (`rotationPolicy: Always`)
- The old certificate is no longer in use by any workload
- It is not exposed externally — no attacker has it
- The security rationale for CRL/OCSP tracking does not apply
- But we are forced into the revocation workflow because there is no alternative

**The middle ground — `CERTIFICATE_HOLD`:**  
Revocation with reason `CERTIFICATE_HOLD` is reversible (can be un-revoked). This does not help the cleanup use case, however — it still creates CRL entries.

---

## 2. EJBCA's Definition of "Renewal" (Obsolete in This Context)

EJBCA's documented "renewal" means: reset EE to NEW → submit CSR with the **same public key** → receive a new cert with a new serial. The old cert stays valid.

This is entirely obsolete for cert-manager workflows where `rotationPolicy: Always` generates a **new key** on each renewal. Each cert-manager renewal is effectively a full new certificate issuance — new key, new serial, new CSR — with all the baggage of a fresh enrolment. The EJBCA "renewal" documentation does not address this scenario at all, adding to the confusion for anyone trying to understand what is happening in EJBCA.

---

## 3. CRL/OCSP Overhead

When a certificate is revoked (even with reason `SUPERSEDED`), it is added to the CRL and tracked by OCSP until it expires. In high-volume short-lived TLS environments, this creates:

- **CRL bloat**: Hundreds or thousands of revoked certs that nobody will ever query
- **OCSP load**: Responder handles status queries for certs nobody cares about
- **Database growth**: Revoked cert records accumulate

**Relevant EJBCA certificate profile options:**

- **"Use Certificate Storage" = disabled**: Certs are not stored in the DB at all ("Throw Away CA" model). Enables very large volumes with no storage, but disables revocation, search, and reporting entirely.
- **"Store Certificate Data" = disabled** (with storage enabled): Stores metadata (revocation status, fingerprint, expiry) but not the full base64 cert. Lighter, but revocation is still tracked.
- **Expired certs are automatically removed from CRLs** per RFC 5280. CRL bloat is therefore self-limiting if cert lifetimes are short (e.g. 47 days).
- **ARCHIVED status**: The CRL creation job sets expired certs to ARCHIVED in the DB. ARCHIVED certs with reason `NOT_REVOKED` or `REMOVEFROMCRL` cause OCSP to respond "not revoked". So expired-but-revoked certs do not persist as "revoked" in OCSP indefinitely, provided the CRL job runs.

**Bottom line**: For short-lived certs (< 90 days), the CRL/OCSP overhead of revocation is bounded by the cert lifetime. The more significant problem is **End Entity accumulation**, not certificate revocation entries.

---

## 4. Single Active Certificate Constraint

**Location**: Certificate Profile → "Other Data" section → "Single Active Certificate Constraint" checkbox. This option is **only visible when Type = "End Entity" is selected**. If editing a Sub CA or Root CA profile, the checkbox is not present. This UI behaviour makes it very easy to miss.

**What it does**: When a new cert is issued for an EE, any existing unrevoked/unexpired certs for that EE are automatically revoked with reason `SUPERSEDED`.

**Important distinction** — this is not the same as CA-level enforce settings:
- `Enforce unique public keys` — prevents two EEs from sharing a key
- `Enforce unique DN` — prevents two EEs from sharing a subject DN

These are CA-level constraints about uniqueness *across* entities. Single Active Certificate Constraint is a cert profile setting about multiple certs *within a single entity*.

**Relevance for cert-manager**: If the EE username is reused across renewals (which is the typical behaviour when `endEntityName: cn` is set in the Issuer resource, and the CN stays constant), enabling this setting causes each renewal to auto-revoke the previous cert. This keeps cert count per EE bounded at 1 active cert.

However: if cert-manager creates a *new* EE for each renewal (e.g. due to a changing CN or `endEntityName` generating a unique value), Single Active Certificate Constraint has no effect on accumulation. The real problem in that case is orphaned EEs, which ELT addresses.

---

## 5. Database Maintenance Service (Enterprise Only)

**What it does**: Automated periodic cleanup of expired certificates and CRLs from the database. Introduced in EJBCA 8.1.

**How it works**: Polls the DB and deletes cert records where `expireDate < (today − delayTime)`.

**Configuration options**:
- CAs to check (selectable per CA)
- Delay after expiration (default: 30 days)
- Delete expired certificates: yes/no
- Delete expired CRLs: yes/no
- Entries to delete per run (default: 100; iterates if more are found)

**Critical limitation**: This service cleans up **certificate data only**. It does **not** clean up **End Entity records**. The `UserData` table is untouched. This is precisely the gap that `ejbca-lifecycle-tool.py` fills — ELT identifies and removes the orphaned EE records that the Database Maintenance Service leaves behind.

**Software Appliance note**: Direct DB access is not available. The required index (`CREATE INDEX certificatedata_idx_exp ON CertificateData (expireDate)`) should be pre-created in appliance builds ≥ 8.1. Configuration is via Admin GUI under Services.

---

## 6. End Entity Profile Settings for cert-manager

The following settings in the End Entity Profile affect cert-manager integration and are commonly misconfigured or poorly documented.

### Username
- **Auto-generated [x]**: EJBCA generates the username, but the cert-manager issuer overrides this by setting the username from the CSR via the `endEntityName` field in the Issuer resource spec.
- `endEntityName` options: `cn`, `dns`, `uri`, `ip`, custom string, or default fallback (CN → DNS → URI → IP → Certificate object name).
- If the CN is constant across renewals (typical for a service), the issuer reuses the same EE username — the EE is **updated** rather than a new one being created. This is the desired behaviour for bounded cert accumulation.

### Password
- **Auto-generated [ ]**: The cert-manager issuer sets a random password for each enrolment request. Leave auto-generated unchecked; the issuer handles it.

### Batch Generation
- **Use [x]**: Required for automated re-enrolment. Without this, EJBCA returns error 400 "No password in request" for cert-manager renewal requests.

### Number of Allowed Requests
- Leave **"Use" unchecked** for unlimited re-enrolment. When "Use" is unchecked, the constraint is not enforced and the EE can be re-enrolled freely. This is correct for cert-manager workflows.

### Allow Renewal Before Expiration
- Leave **unchecked**. The cert-manager EJBCA issuer uses the PKCS10 Enroll endpoint, which resets the EE to `NEW` status on each request — bypassing the `GENERATED`-status check entirely. This EJBCA feature is not relevant to the cert-manager workflow.

### Why Configuration is Poorly Documented

- Keyfactor's documentation assumes manual/interactive PKI workflows
- The cert-manager issuer is community-contributed (Keyfactor open source) with no SLA
- The issuer is a thin REST API wrapper and does not document the required EJBCA-side configuration
- Vendor support may not have deep cert-manager integration experience — PKI vendors think in CA terms; Kubernetes users think in automation terms

---

## 7. Cleanup Strategy

For cert-manager + EJBCA with short-lived TLS certs, cleanup operates at several layers:

| Layer | What it cleans | Who does it | Availability |
|-------|---------------|-------------|--------------|
| cert-manager | K8s Secrets, CertificateRequests | cert-manager itself | Always |
| Single Active Cert | Old certs (auto-revoke on renewal) | EJBCA cert profile | Enterprise; only if same EE is reused |
| Database Maintenance | Expired cert records from DB | EJBCA service | Enterprise 8.1+ |
| **ejbca-lifecycle-tool.py** | **Orphaned End Entities; cert accumulation** | **Admin / cron** | **Always (REST API)** |
| CRL expiry | Revoked certs drop off CRL after `notAfter` | Automatic per RFC 5280 | Always |

**The gap**: Nobody cleans up End Entities. Not cert-manager (it has no visibility into EJBCA EE records), not EJBCA's Database Maintenance Service (it handles cert data only, not the `UserData` table), and not the CRL process. `ejbca-lifecycle-tool.py` fills this gap.

A further gap: there is currently no REST API endpoint to delete individual certificate records (`DELETE /v1/certificate/{issuer}/{serial}` does not exist). Revocation is the furthest the API goes. This limits cleanup of revoked-but-unexpired certs — the Database Maintenance Service is the only mechanism, and it only acts after `notAfter`. This is a feature request worth raising with Keyfactor.

---

## 8. Software Appliance Constraints

- No direct database access (no SQL queries, no manual index creation)
- No access to internal configuration files (e.g. `ejbca.properties`)
- All configuration via Admin GUI or REST API
- Database Maintenance Service index should be pre-created in appliance builds ≥ 8.1
- `ejbca-lifecycle-tool.py` uses only the REST API and works fully with appliance deployments — no special access is required

---

## 11. EJBCA Configuration Checklist for cert-manager Integration

### CA Configuration
*(applies only to the Issuing CA referenced by the End Entity Profile)*

- [ ] **Enforce unique public keys** — **unchecked** (cert-manager generates new keys each renewal with `rotationPolicy: Always`)
- [ ] **Enforce unique DN** — **unchecked** (same CN reused across renewals)
- [ ] **Finish User** — **checked** (password not blanked for User Generated tokens)

### Certificate Profile *(Type: End Entity)*
*(applies only to the Leaf certificate profile referenced by the End Entity Profile)*

- [ ] Key algorithm and size match the cert-manager Certificate spec
- [ ] **Validity** — **47 days** recommended for cert-manager-managed certs (short-lived, auto-renewed)
- [ ] **Allow Validity Override** — **checked** (needed once the cert-manager issuer passes requested validity to EJBCA; see Known Gaps below)
- [ ] **Single Active Certificate Constraint** — **checked** (auto-revokes previous cert on renewal, if same EE is reused)
- [ ] CRL Distribution Points / OCSP responder URLs configured as required

### End Entity Profile
*(applies only to the EE profiles used by cert-manager enrolments)*

- [ ] Subject DN fields match what cert-manager will send in the CSR
- [ ] **Username: Auto-generated** — checked (cert-manager issuer overrides as needed)
- [ ] **Password: Required / Auto-generated** — both unchecked (issuer sets a random password per enrolment)
- [ ] **Batch generation: Use** — **checked** (avoids "No password in request" error 400)
- [ ] **Number of allowed requests: Use** — **unchecked** (unlimited re-enrolment)
- [ ] **Default Token** — User Generated (cert-manager generates keys client-side)
- [ ] **Allow Renewal Before Expiration** — **unchecked** (not applicable to cert-manager workflow)

### Issuer Resource (Kubernetes)
- [ ] `endEntityProfileName` matches the EE profile name exactly
- [ ] `certificateProfileName` matches the cert profile name exactly
- [ ] `certificateAuthorityName` matches the CA name exactly
- [ ] `endEntityName: cn` — recommended, to ensure EE reuse across renewals (avoids orphan accumulation)
- [ ] `ejbcaSecretName` points to a valid client cert/key secret

### Role and Access Rules
- [ ] RA Administrator role created for cert-manager with appropriate access
- [ ] REST Certificate Management protocol enabled
- [ ] Role authorised for the correct CAs and EE profiles
- [ ] `/system_functionality/view_systemconfiguration/` added (needed for `elt count` global totals)
- [ ] Trusted CA list includes the CA of the access certificate

### Database Maintenance Service *(Enterprise, recommended)*
- [ ] Service created and enabled
- [ ] CAs to Check: all relevant CAs
- [ ] Delay After Expiration: minimum allowed (DEV: 1 day; PROD: per compliance policy)
- [ ] Delete Expired Certificates: true
- [ ] Delete Expired CRLs: true
- [ ] Entries per run: 1000–5000 (increase for large backlogs)

---

## Known Gaps

**¹ cert-manager `duration` ignored by EJBCA** — The certificate duration requested in the Kubernetes Certificate resource is not passed to EJBCA. The Certificate Profile validity always takes precedence. Workaround: set `renewBefore` relative to the actual EJBCA-issued validity, not the requested duration. Fix pending: [Keyfactor issue #128]( https://github.com/Keyfactor/ejbca-cert-manager-issuer/issues/128 )

**² Revoked records not purged until expiry** — EJBCA's Database Maintenance Service only deletes *expired* certificate records. Revoked certificates with long nominal lifetimes (e.g. 2 years) remain in the database until they expire, even if revoked shortly after issuance. Short-lived certificate profiles (e.g. 47 days) bound this: revoked records are purged within weeks of expiry.

**³ No REST API endpoint to delete certificate records** — `DELETE /v1/certificate/{issuer}/{serial}` does not exist. Revocation is the furthest the API goes. Direct database cleanup must be done via the Database Maintenance Service (expired certs only) or the EJBCA admin CLI (not available on the Software Appliance).

**⁴ EE-level revoke returns HTTP 500** — `PUT /v1/endentity/{username}/revoke` may return a 500 error for some EE types. Workaround: use per-certificate revocation (`elt cleanup -keep-newest 0`), which calls the cert-level revoke endpoint per serial.

**⁵ Ghost certificate records** — When an EE is deleted from EJBCA, its certificate records persist in the database until `notAfter` + the Database Maintenance Service delay. These records are visible via the cert search API but the EE record is gone. `elt -ghosts` detects and displays these. They do not block re-creation of the same EE username.
