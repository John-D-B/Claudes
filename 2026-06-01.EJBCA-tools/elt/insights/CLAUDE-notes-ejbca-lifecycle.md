# CLAUDE Notes: EJBCA Certificate Lifecycle with cert-manager

Running notes from the ejbca-lifecycle-tool (ELT) development sessions.
Last updated: 2026-03-09

---

## 1. The "Expire vs Revoke" Question

**Q: Can you just "expire" an old certificate instead of revoking it?**

No. Expiration is passive — it happens when `notAfter` arrives. There's no API call
to accelerate it. If a cert is valid until 2028 and you want it invalid now, revocation
is the only mechanism.

This is a **very common question/frustration** in the EJBCA community. The mental
model mismatch is real: "renew" intuitively means a regular, expected lifecycle event
(like renewing a driver's license), but in PKI, the old cert doesn't go away — it
lingers until its natural expiration, and the only way to kill it early is revocation,
which carries the connotation of an emergency or punitive action.

**The practical reality for cert-manager + short-lived TLS certs:**
- cert-manager creates new keys, new CSR, new serial on each renewal
  (`rotationPolicy: Always`)
- The old cert is no longer in use by any workload
- It's not "in the wild" — no attacker has it
- The security rationale for CRL/OCSP tracking doesn't apply
- But we're forced into the revocation workflow because there's nothing else

**The middle ground — `CERTIFICATE_HOLD`:**
Revocation with reason `CERTIFICATE_HOLD` is reversible (can be un-revoked).
But this doesn't really help the cleanup use case — it still creates CRL entries.


## 2. EJBCA's Definition of "Renewal" (Obsolete in Our Context)

EJBCA's documented "renewal" means: reset EE to NEW → submit CSR with **same
public key** → get new cert with new serial. The old cert stays valid.

This is obsolete for cert-manager workflows where `rotationPolicy: Always` generates
a **new key** each time. Each renewal is effectively a full new certificate — new key,
new serial, new CSR — with all the baggage of a fresh issuance. The EJBCA "renewal"
docs don't address this at all, adding to the confusion.


## 3. The CRL/OCSP Overhead Problem

When we revoke (even with SUPERSEDED), the cert is added to the CRL and tracked
by OCSP until it expires. For high-volume short-lived TLS certs, this creates:

- **CRL bloat**: Hundreds/thousands of revoked certs that nobody will ever query
- **OCSP load**: Responder handles status queries for certs nobody cares about
- **Database growth**: Revoked cert records accumulate

**Can we skip CRL/OCSP tracking?**

There's no clean way per-certificate, but EJBCA has some relevant settings:

- **"Use Certificate Storage" = disabled** in the certificate profile: Certs are
  not stored in the DB at all. This is the "Throw Away CA" / "fire and forget"
  model. Enables billions of certs with no storage. BUT: disables revocation
  entirely, search, reporting — everything that depends on cert data.

- **"Store Certificate Data" = disabled** (with Use Certificate Storage enabled):
  Stores metadata (revocation status, fingerprint, expiry) but not the actual
  cert data (base64Cert). Lighter, but still tracks revocation.

- **Expired certs are automatically removed from CRLs** per RFC 5280. So the CRL
  bloat is self-limiting if cert lifetimes are short (e.g., 90 days). After
  expiry, the cert drops off the CRL regardless of revocation status.

- **ARCHIVED status**: The CRL creation job sets expired certs to ARCHIVED in the
  DB. ARCHIVED with reason NOT_REVOKED or REMOVEFROMCRL → OCSP responds "not
  revoked". So expired-but-revoked certs don't linger as "revoked" in OCSP
  indefinitely IF the CRL job runs.

**Bottom line**: For short-lived certs (< 90 days), the CRL/OCSP overhead of
revocation is bounded by the cert lifetime. The real problem is the **End Entity
accumulation**, not the certificate revocation entries.

**Alternative approach — just delete the EE without revoking:**
If the cert is truly not in use and will expire shortly, you could skip revocation
and just delete the End Entity. The cert itself remains in the DB until cleaned up
by the Database Maintenance Service. This avoids CRL/OCSP entries entirely. The
trade-off is that the cert is technically "valid" until expiry but with no EE
backing it. For internal TLS certs that cert-manager has already replaced, this
may be perfectly acceptable.

**TODO**: Consider adding a `--delete-only` mode to ELT that skips revocation
and just deletes the EE. Relevant for short-lived internal TLS certs where CRL
tracking is pure waste.


## 4. Single Active Certificate Constraint

**Where it lives**: Certificate Profile → "Other Data" section → "Single Active
Certificate Constraint" checkbox. **Only visible when Type = "End Entity" is
selected.** If you're editing a Sub CA or Root CA profile, the checkbox disappears
entirely. This UI behavior makes it very hard to find — you have to be editing
the right type of profile to even see the option.

**Confirmed in screenshots** (2026-03-04):
- Certificate Profile: `home_SG-Leaf` (Type: End Entity, ID: 1426534281)
- "Single Active Certificate Constraint" checkbox: **not checked** (current state)
- Located at very bottom of profile page, under "Other Data"

**What it does**: When a new cert is issued for an EE, any existing unrevoked/
unexpired certs for that EE are automatically revoked with reason SUPERSEDED.

**NOT the same as the CA-level enforce settings:**
- `Enforce unique public keys` → prevents two EEs from using the same key
- `Enforce key renewal` → requires new key for renewal  
- `Enforce unique DN` → prevents two EEs from sharing a subject DN
- `Enforce unique Subject DN SerialNumber` → prevents shared serial in DN

These are **CA-level constraints** about uniqueness across entities.
Single Active Certificate Constraint is a **cert profile** setting about
multiple certs within a single entity.

**Relevance for cert-manager**: If enabled, each renewal auto-revokes the
previous cert. This is helpful but doesn't solve the EE accumulation problem
because cert-manager creates new EEs, not new certs for the same EE.

**IMPORTANT**: The cert-manager EJBCA issuer uses the CN (or DNS name, etc.)
as the EE username. If the CN stays the same across renewals, the issuer
reuses/updates the existing EE. If it changes, a new EE is created. This
behavior determines whether Single Active Certificate Constraint helps.


## 5. Database Maintenance Service (Enterprise Only)

**What**: Automated periodic cleanup of expired certificates and CRLs from the
database. Added in EJBCA 8.1.

**How**: Polls DB, deletes certs where `expireDate < (today - delayTime)`.

**Configuration**:
- CAs to check (selectable)
- Delay after expiration (default: 30 days)
- Delete expired certificates: yes/no
- Delete expired CRLs: yes/no
- Entries to delete per run (default: 100, iterates if more)
- Requires DB index: `CREATE INDEX certificatedata_idx_exp ON CertificateData (expireDate)`

**Critical limitation**: Cleans up **certificate data** only. Does NOT clean up
**End Entity records**. The UserData table is untouched. This is exactly the gap
that ELT fills.

**Software Appliance note**: Since there's no direct DB access, the index must
already be present (it should be if running 8.1+), and configuration is via the
Admin GUI under Services.


## 6. End Entity Profile Settings for cert-manager

### Username
- **Auto-generated [x]**: EJBCA generates the username. But the cert-manager
  issuer overrides this by setting the username from the CSR (CN, DNS name, etc.)
  via the `endEntityName` field in the Issuer resource spec.
- The issuer's `endEntityName` options: `cn`, `dns`, `uri`, `ip`, custom string,
  or default fallback (CN → DNS → URI → IP → Certificate object name).
- If the CN stays the same across renewals (typical for a service), the issuer
  reuses the same EE username, which means the EE is **updated** rather than
  a new one created. This is the desired behavior.

### Password
- **Auto-generated [ ]**: Password is not auto-generated. The cert-manager issuer
  sets a random password for each enrollment request.
- This should work fine. The issuer handles it.

### Batch generation
- **Use [x]**: Allows server-side key generation (P12/JKS). With cert-manager,
  keys are always generated client-side (in the cluster), so this setting
  shouldn't matter for the cert-manager workflow. But it doesn't hurt.

### Key settings that matter

- **"Number of allowed requests"** in EE profile (Other Data section):
  Has a "[ ] Use" checkbox and "Default = 1" dropdown. The documentation
  claims "set to 0 for unlimited" but the description is confusing and
  arguably wrong — what's the alternative, a negative number?
  
  **Confirmed in screenshots** (2026-03-04):
  - "[ ] Use" checkbox: **not checked** (current state)
  - Default = 1 (dropdown value)
  - No ill effects observed with cert-manager renewals when unchecked
  - This appears to be a manual-workflow feature; when "Use" is unchecked,
    the constraint is not enforced, and the EE can be re-enrolled freely.
  - Also visible: "Allow renewal before expiration" (not checked),
    "Revocation reason to set after certificate issuance" (not checked),
    "Redact Subject Name from logs" (not checked)

- **"Finish user" in CA settings**: If unchecked, status stays NEW after
  issuance. Alternative to "Number of allowed requests".
- One of these may need to be configured for cert-manager renewals, but
  in practice, the cert-manager EJBCA issuer uses the PKCS10 Enroll REST
  endpoint which creates/updates the EE as part of enrollment, bypassing
  the status check issue entirely.

### Why the config is poorly documented
- Keyfactor's docs assume manual/interactive PKI workflows
- cert-manager integration is community-contributed (Keyfactor open source)
- The cert-manager issuer is a thin REST API wrapper; it doesn't document
  the EJBCA-side configuration needed
- The "it depends on your use case" answer is technically correct but
  unhelpful for the specific cert-manager + short-lived TLS scenario
- Vendor support may not have deep cert-manager integration experience
  (PKI vendors think in CA terms; K8s users think in automation terms)


## 7. Cleanup Strategy Summary

For cert-manager + EJBCA with short-lived TLS certs, the cleanup layers are:

| Layer | What it cleans | Who does it | Available |
|-------|---------------|-------------|-----------|
| cert-manager | K8s secrets, CertificateRequests | cert-manager itself | Always |
| Single Active Cert | Old certs (auto-revoke) | EJBCA cert profile | Enterprise, if same EE reused |
| Database Maintenance | Expired cert data from DB | EJBCA service | Enterprise 8.1+ |
| **ELT (this tool)** | **Orphaned End Entities** | **Admin / cron** | **Always (REST API)** |
| CRL expiry | Revoked certs drop off CRL | Automatic per RFC 5280 | Always |

**The gap**: Nobody cleans up End Entities. Not cert-manager (it doesn't know about them),
not EJBCA's Database Maintenance Service (it only handles certs), not the CRL process.
ELT fills this gap.


## 8. Software Appliance Constraints

- No direct DB access (no SQL queries, no manual index creation)
- No direct access to internal config files (e.g., `ejbca.properties`)
- All configuration via Admin GUI or REST API
- Database Maintenance Service index should be pre-created in appliance builds ≥ 8.1
- ELT uses only the REST API, so it works with appliance deployments


## 9. Open Questions / Future Investigation

- [x] Should ELT support `--delete-only`? **YES — implemented in v1.16.0**
- [x] What does the cert-manager EJBCA issuer set as EE username?
      **Confirmed**: CN-based names for cert-manager certs, hex hashes for
      some auto-generated EEs. Varies by EE profile config and issuer spec.
- [x] Pagination bug causing 500 cert ceiling? **Fixed in v1.23.3** — EJBCA's
      `total_certs` is unreliable; now uses page fullness detection.
- [x] False orphans in `lca`? **Fixed in v1.23.4** — `build_profile_map()`
      limit was too low; raised to `--max-certs` (default 10000).

→ See **section 17** for remaining open items.


## 10. ELT Development Status

→ See **section 16** for current status (v1.24.2).

**Known EJBCA REST API issues**: See **section 14**.


## 11. EJBCA Configuration Checklist for cert-manager Integration

Settings needed for cert-manager + EJBCA + ELT to work cleanly:

### CA Configuration
- [ ] "Enforce unique DN" — **unchecked** if you need multiple certs for
      same subject (common in cert-manager renewals)
- [ ] "Enforce unique public keys" — **unchecked** (cert-manager generates
      new keys each renewal with `rotationPolicy: Always`)

### Certificate Profile (Type: End Entity)
- [ ] Key algorithm and size must match cert-manager Certificate spec
- [ ] Validity period appropriate for your use case
- [ ] "Single Active Certificate Constraint" — **consider enabling** if
      the EE is reused across renewals (auto-revokes old cert)
- [ ] CRL Distribution Points / OCSP responder URLs configured as needed

### End Entity Profile
- [ ] Subject DN fields match what cert-manager will send
- [ ] "Username" — auto-generated is fine; cert-manager issuer overrides
- [ ] "Number of allowed requests" — leave "Use" unchecked for simplicity
- [ ] "Batch generation: Use" — check if using server-side key generation

### Issuer Resource (Kubernetes)
- [ ] `endEntityProfileName` matches the EE profile name exactly
- [ ] `certificateProfileName` matches the cert profile name exactly
- [ ] `certificateAuthorityName` matches the CA name exactly
- [ ] `endEntityName` — consider setting to `cn` to ensure EE reuse
      across renewals (avoids orphan accumulation)
- [ ] `ejbcaSecretName` points to valid client cert/key secret

### Role & Access Rules
- [ ] RA role created for cert-manager with appropriate access
- [ ] REST Certificate Management protocol enabled
- [ ] Role authorized for the correct CAs and EE profiles


## 12. Why We Seem to Be the Only Ones Deep Diving

Several factors converge:

1. **Keyfactor sells to enterprise CA admins**, not K8s platform teams.
   Their docs, support, and mental model are "admin manages entities via
   GUI" not "automation pipeline creates thousands of ephemeral certs."

2. **cert-manager is infrastructure plumbing** — it "just works" for the
   K8s team. They don't look at what's happening in EJBCA because their
   pods get certs. The CA side is someone else's problem.

3. **The orphan problem is slow-growing**. It doesn't cause failures; it
   causes DB bloat that surfaces months later as performance degradation
   or audit findings. Easy to ignore until it's not.

4. **The cert-manager EJBCA issuer is community-contributed.** Keyfactor
   maintains it as open source but there's no SLA. The gap between
   "issue a cert" and "manage the full lifecycle" is left as an exercise.

5. **The CRL/OCSP waste** is invisible to anyone not monitoring CA metrics.
   Nobody notices until the CRL gets large or OCSP response times increase.

6. **Documentation silo**: EJBCA docs cover EJBCA. cert-manager docs cover
   cert-manager. Nobody documents the integration lifecycle end-to-end
   with realistic automation scenarios and cleanup strategies.

This is publishable. The combination of ELT + these notes + the config
checklist fills a real gap in the community documentation.


## 13. REF Environment Findings (2026-03-05)

### Cert Accumulation — The Core Problem Observed

In the REF (reference/test) environment with 3308 total certificates:

- **"Renewal Hourly"** EE: 1 End Entity, **1504 active certs** accumulated
  (hourly cert-manager renewal creating ~24 certs/day)
- **"Luke Skywalker"** EE: 1 End Entity, **1247 active certs** accumulated
  (similar pattern, different renewal schedule)
- 37 End Entities total, 3207 certs tied to EEs
- Gap of 101 certs = CA certs, management certs without end-entities

All certs are Active status — none revoked, none expired yet (3-year validity).
cert-manager is doing its job (rotating keys, issuing new certs), but the
old certs are piling up in EJBCA with no cleanup mechanism.

**Confirmed numbers (v1.23.3, 2026-03-06):**
- Global: Total=3308, Active=3273, Inactive=35
- Per-EE: 3207 certs across 37 EEs (3207 active, 0 revoked)

### The Two Cleanup Problems Are Now Distinct

1. **Orphaned End Entities** (what ELT currently solves):
   EEs that no longer have a matching K8s Certificate. Delete the EE.

2. **Accumulated Certificates per EE** (newly identified):
   EEs that ARE still active in K8s, but have dozens/hundreds of old
   certs that are no longer in use. The EE itself is fine — it's the
   old certs under it that are waste.

   This is where "Single Active Certificate Constraint" would help
   (auto-revoke old cert on new issuance), or a new ELT feature to
   revoke/delete old certs while keeping the current one.

### REST API Cert Search Limitation

The `build_profile_map()` approach (searching with `QUERY LIKE %`) had a
scaling problem: with 3000+ certs, the search didn't return all usernames
within the result limit, causing false orphans in `lca` output.

**Fixed in v1.23.4**: All `build_profile_map()` calls now use `--max-certs`
(default 10000), and pagination was fixed (see section 14, bug #1).

For per-EE cert counts, ELT now uses targeted cert searches per username
(`search_certs_for_username`), which is accurate regardless of total cert count.

### EJBCA GUI Behavior (Confirmed)

The GUI is actually consistent, just confusing:
- **Search End Entities** (Admin GUI): Shows 1 EE per username (correct)
- **Search Certificates** (RA Web): Shows ALL certs matching a CN (correct)
- **View End Entity**: Shows the EE details AND lists all its certificates

The REST API EE search returns the EE but not its certificates. The REST
API cert search returns certificates but may miss some due to pagination.
There's no single API call that says "give me EE X and all its certificates."

### Impact Assessment

With hourly renewal and 3-year cert validity:
- Per CN: ~8,760 certs/year, ~26,280 over validity period
- With N services: N × 26,280 active cert records in EJBCA
- **Observed in REF**: 1504 certs for one hourly EE in ~6 weeks
- CRL impact: None (certs aren't revoked, so not on CRL)
- OCSP impact: All certs respond "good" (technically correct but wasteful)
- DB impact: Significant — each cert record includes full base64 cert data

**Recommendation**: Enable "Single Active Certificate Constraint" in the
certificate profile. This auto-revokes old certs with SUPERSEDED on each
renewal. Combined with Database Maintenance Service (to purge expired
certs after a grace period), this keeps the DB bounded.

For existing accumulation: Consider a new ELT feature to revoke old certs
per EE, keeping only the most recent N.


## 14. EJBCA REST API Bugs and Workarounds (Confirmed 2026-03-06)

### Bug 1: Certificate search `total_certs` is unreliable

The `/v2/certificate/search` endpoint's `pagination_summary.total_certs`
field reports the PAGE count, not the true total, until the last page.

**Example**: With 1504 certs, page 1 returns 500 certs and
`total_certs: 500`. The old code saw `500 >= 500` and stopped.

**Workaround** (v1.23.3): Use page fullness instead of `total_certs` to
decide whether to continue. If a page returns `page_size` results (500),
there might be more → keep fetching. Partial page = last page.

Confirmed by EJBCA community: https://github.com/Keyfactor/ejbca-ce/discussions/600

### Bug 2: `isActive=false` doesn't mean "count inactive"

The `/v2/certificate/count?isActive=false` parameter doesn't mean "count
inactive certificates." It means "don't filter by active status" — returning
the same count as omitting the parameter entirely.

**Evidence**: REF system: Total=3308, `isActive=false`=3308. Identical.
DEV system: Total=23, Active=16, `isActive=false`=23. Same as total.

**Workaround** (v1.23.2): Compute Inactive = Total − Active. Don't call
the `isActive=false` endpoint at all.

### Bug 3: EE search doesn't return profile fields

The `/v2/endentity/search` endpoint omits `endEntityProfile`,
`endEntityProfileId`, and `certificateProfile` from results.

**Workaround**: `build_profile_map()` fetches profile data via the
`/v2/certificate/search` endpoint (which does return these fields) and
merges them into the EE records client-side.

### Bug 4: EE profile filtering via search API is broken

The `END_ENTITY_PROFILE` search criterion returns 400 ("unknown end
entity profile") even with valid numeric IDs. Confirmed broken in
EJBCA 9.2.3.

**Workaround**: Fetch all EEs, filter client-side using enriched profile
data from the certificate search.

### API quirk: Certificate count requires system_functionality access

The `/v2/certificate/count` endpoint requires the access rule
`/system_functionality/view_systemconfiguration/`, which is NOT included
in the standard "RA Administrators" role template. To use it, the role
must be switched to "Custom" and this rule added manually.

This is arguably a Keyfactor oversight — counting certificates is a
read-only RA function, not a system configuration task. The RA role
already has access to search and view certificates; counting them
shouldn't require elevated privileges.

### API quirk: `extension_data` can be None, not empty list

Some EEs return `extension_data: null` instead of `extension_data: []`.
Code iterating over this field must use `isinstance(ext_data, list)`
guard, not `ext_data or []` (which fails on other truthy non-iterables).

### API bug: EE-level revoke returns 500 "General failure"

`PUT /v1/endentity/{name}/revoke` returns 500 "General failure" for some
EEs, particularly those with Token: PEM (EJBCA-generated keys). The
per-cert revoke endpoint (`PUT /v1/certificate/{issuer}/{serial}/revoke`)
works correctly for the same certificates. Confirmed 2026-03-09 on
EJBCA 9.3.3 Enterprise.

Workaround: use per-cert revocation (ELT's `--keep-newest 0`).

### API limitation: No certificate deletion endpoint

There is no REST API endpoint to delete a certificate record from the
database. `DELETE /v1/endentity/{name}` removes the EE but leaves cert
records in `CertificateData`. These "ghost certs" persist indefinitely,
inflate global cert counts and license totals, and are only removable
via Database Maintenance Service (Enterprise, scheduled) or direct SQL.


## 15. EJBCA Configuration Observations

### Proxy interference with mTLS

Python's `requests` library picks up proxy settings from multiple sources
beyond just `HTTP_PROXY`/`HTTPS_PROXY` — it reads system config, `.netrc`,
and other environment sources via `trust_env`. The `--no-proxy` flag was
added to ELT to explicitly disable this with `session.trust_env = False`.

### Private CA trust

When EJBCA's server cert is signed by a private CA, `--ca-cert` (or
`ELT_CA_CERT`) is required. Without it, the SSL handshake fails with
"self-signed certificate in certificate chain." Using `--no-verify-ssl`
works but bypasses all server certificate validation.

### Role permissions for ELT

Minimum EJBCA role for ELT (read-only operations):
- Role Template: RA Administrators (or Custom)
- Authorized CAs: select relevant CAs
- End Entity Rules: View End Entities
- End Entity Profiles: select relevant profiles
- For certificate count: add `/system_functionality/view_systemconfiguration/`
  (requires Custom role template)


## 16. ELT Development Status

**Current version**: 2.3.0 (major restructure from v1.x)

**Commands**:
| Command | Shortcut | Description |
|---------|----------|-------------|
| `ping` | — | Verify REST API connectivity |
| `list -d1` | `list1` | EE Profile names + IDs |
| `list -d2` | `list2` | + associated Certificate Profiles |
| `list -d3` | `list3` | + EE usernames with cert counts |
| `list -d4` | `list4` | + full certificate tables per EE |
| `count` | — | Cert count overview (sorted by accumulation) |
| `cleanup` | — | Revoke/delete orphaned EEs |

**Filtering** (works across all commands):
- `--ee-profile NAME_OR_ID` — auto-detects name vs numeric ID, also `orphans`
- `--ee-username NAME` — single EE drill-down
- `--active` / `--revoked` — filter by cert status
- `-F` / `--full` — show all items (default: first 3, then truncate)

**Key features**:
- Certificate display (`-ci`, `-ci2` for full DN) in list -d4
- K8s cross-reference (`--k8s-compare`) in list -d3 and cleanup
- Environment variable support (`ELT_HOST`, `ELT_CERT`, `ELT_KEY`, `ELT_CA_CERT`)
- `--delete-only` mode (skip revocation, no CRL/OCSP overhead)
- `--no-proxy` for direct mTLS bypassing corporate proxies
- `(orphans)` virtual profile for entities without EJBCA profile
- Cert profile grouping in section banners (single/multiple/unknown)
- Progressive output with `sys.stdout.reconfigure(line_buffering=True)`
- Version stamp in every action output for `| tee` tracking

**Known EJBCA REST API issues**: See section 14 above


## 17. Next Steps

- [ ] Test cleanup operations (`--delete-only`, revoke+delete) on DEV
- [ ] Verify: does `--delete-only` actually skip CRL/OCSP entries?
- [ ] Does EJBCA allow deleting an EE with active (unrevoked) certs?
- [ ] Test enabling "Single Active Certificate Constraint" on cert profile
- [ ] Monitor REF cert accumulation rate after any config changes
- [ ] Consider ELT feature: revoke old certs per EE, keep most recent N
- [ ] Publish findings to Keyfactor / community for feedback
- [ ] Document complete EJBCA + cert-manager configuration checklist
- [ ] Investigate deterministic username generation for multi-tenancy (section 18)
- [ ] Report cross-profile authorization violation to Keyfactor (section 19)
- [ ] Enable Database Maintenance Service on all EJBCA instances (section 20)
- [ ] Create certificatedata_idx_exp index before enabling DMS (section 21)
- [ ] Request REST API cert deletion endpoint from Keyfactor (section 20)
- [ ] Propose 47-day TLS cert lifetime for cert-manager profiles (section 21)
- [ ] Review short-cert strategy with internal IT security team (section 21)


## 18. Multi-Tenancy Landmine: EE Username Global Uniqueness

**Problem discovered 2026-03-07**: EJBCA enforces globally unique usernames
across the entire instance. The cert-manager EJBCA issuer defaults to using
the certificate's CN as the EE username. In a multi-tenant environment,
this creates silent collisions.

### Scenario

Tenant A in namespace `team-a` requests:  `CN=web-server`
→ EJBCA creates EE username `web-server` under Profile-A ✓

Tenant B in namespace `team-b` requests:  `CN=web-server`
→ EJBCA rejects: username `web-server` already exists ✗

Tenant B gets a cryptic error with no indication that the name is taken
by a different tenant in a different profile.

### How `endEntityName` Works (from issuer docs)

The `endEntityName` field in the Issuer spec controls how the EE username
is derived. Default fallback chain:
1. CN from CSR
2. First DNS Name from SAN
3. First URI from SAN
4. First IP Address from SAN
5. cert-manager Certificate resource name

Options: `cn`, `dns`, `uri`, `ip`, `certificateName`, or a static string.

### EJBCA Auto-Generated Usernames Don't Help

EJBCA's RA Web supports "Auto-generated" usernames (producing hex IDs like
`87600ad8c1ae28c5bb40f880c7af8626`). But this can't work with cert-manager:

1. **REST API requires username in the request** — the PKCS10 Enroll endpoint
   has `username` as a required field. There's no "create and tell me what
   you named it" flow.
2. **Issuer has no state persistence** — even if EJBCA returned the generated
   username, the issuer has nowhere to store the mapping between the
   cert-manager Certificate resource and the EJBCA username.
3. **Renewals need the same username** — cert-manager reuses the EE on renewal
   by calling the API with the same username. Without storing the auto-generated
   name, the issuer can't find the EE again.

### Observed in Testing

REF environment, EE Profile `XXX-CA-05-End-Entity`:
- `87600ad8c1ae28c5bb40f880c7af8626` — auto-generated via RA Web enrollment
- `k8s-cert-d42f.pkirules` — from cert-manager (CN-based)

The auto-generated one works for one-shot RA Web use but is orphaned from
cert-manager's perspective — cert-manager can't manage its lifecycle.

### Proposed Enhancement: Deterministic Unique Username

The issuer could generate usernames by hashing deterministic inputs:

```
username = sha256(namespace + "/" + name + "/" + issuerRef)[:32]
```

For example: `team-a/web-server/ejbca-issuer` → `a7f3b2c1d4e5...`

This would be:
- **Globally unique** across tenants (includes namespace)
- **Deterministic** (same inputs always produce same hash)
- **Reproducible on renewal** (no state storage needed)
- **No EJBCA changes required** (just an issuer-side change)

This would need to be a feature request to the Keyfactor EJBCA issuer project.

### K8s Secret Already Has Issuer Metadata

Confirmed by examining a live cert-manager Secret (`kubectl get secret -o json`):
the `metadata.annotations` already contains rich issuer context:

```
cert-manager.io/certificate-name: k8s-cert-52b9
cert-manager.io/common-name: JohnB.server-test-47.apps.XXX
cert-manager.io/issuer-name: pkirules-tls
cert-manager.io/issuer-kind: Issuer
cert-manager.io/issuer-group: ejbca-issuer.keyfactor.com
cert-manager.io/alt-names: localhost,k8s-cert-52b9.pkirules
```

A custom annotation like `ejbca-issuer.keyfactor.com/end-entity-name` would
fit naturally here. The issuer controller already has RBAC access to Secrets
(it reads its own client cert from one), so annotating the cert Secret after
enrollment is a minimal change.

### Workarounds Until Then

1. `endEntityName: dns` — use SAN DNS name (more likely unique as FQDN)
2. `endEntityName: certificateName` — use cert-manager resource name
   (unique per namespace, but not globally)
3. Naming conventions — require tenant-prefixed CNs
4. Separate EJBCA instances per tenant (expensive)
5. **Secret annotation approach** — the issuer could store the EJBCA
   username as a custom annotation on the K8s Secret after enrollment:
   `ejbca-issuer.keyfactor.com/end-entity-name: <username>`
   On renewal, the issuer reads this annotation to find the existing EE.
   cert-manager doesn't care about extra annotations on the Secret —
   it manages `cert-manager.io/*` and ignores others. This would require
   only an issuer change, no cert-manager core changes, and would work
   with any username strategy including EJBCA's native auto-generate.
   Tradeoff vs deterministic hash: adds a K8s write + annotation dependency,
   but supports any username strategy.


## 19. CONFIRMED: Cross-Profile Authorization Violation (2026-03-08)

### Summary

When two cert-manager issuers with different authorization contexts request
certificates with the same CN (= same EE username), EJBCA's PKCS10 Enroll
endpoint silently **re-profiles the existing End Entity** to the second
issuer's profile — crossing authorization boundaries. This is a security
bug, not just a usability issue.

### Test Setup

Three access certificates with different EJBCA role permissions:
- `IAC-ELT-test-2.CERT.pem` — role access only to tenant `PS-CLS-CBCD`
- `IAC-ELT-test.CERT.pem` — role access only to tenant `PS-PSC-FA2`
- `cert_rhos_test.CERT.pem` — role access to all tenants

### What Happened

**Step 1** (19:38:14 UTC): Request `CN=JohnB-2 test` for tenant CBCD.
- EJBCA creates EE username `JohnB-2 test` under profile
  `XX-REF-RHOS-PS-CLS-CBCD-CA-03-End-Entity`
- Certificate issued: serial `6a:c1:93:1b:...`
- Everything correct.

**Step 2** (19:50:29 UTC): Switch to FA2 credentials. Request `CN=JohnB-2 test`
for tenant FA2.
- EJBCA finds existing EE `JohnB-2 test` (under CBCD profile)
- Instead of rejecting (FA2 creds have no access to CBCD), EJBCA **silently
  moves the EE** from CBCD profile to FA2 profile
- New certificate issued: serial `71:97:e7:a7:...`
- Original cert `6a:c1:...` is now also under FA2 profile

### Consequences Observed

1. **Authorization boundary crossed**: The FA2 credential modified an EE
   it had no access to. The CBCD access cert can no longer see its own
   certificate.

2. **EE profile silently changed**: The EE moved from CBCD to FA2 without
   any error or warning. All certs previously issued under CBCD are now
   associated with FA2.

3. **Ghost certificate appeared**: A third cert (serial `d5:0b:1e:70:...`)
   appeared with the **exact same NotBefore/NotAfter** as the first cert
   (same second: `Mar 08 19:38:14 2026 GMT`) and the same SAN
   (`k8s-cert-6faa.pkirules-ref`). This indicates EJBCA issued two
   certificates from the same CSR in the same request — likely a retry
   by the cert-manager issuer during the first enrollment.

4. **Ghost cert invisible to both tenants**: The ghost cert is only visible
   via the "all tenants" access cert, not via either individual tenant's
   access cert. This creates an orphaned cert that no tenant admin can manage.

5. **K8s Secret metadata stale**: The K8s Secret still shows
   `cert-manager.io/subject-organizationalunits: PS-CLS-CBCD` — the original
   tenant. cert-manager has no idea the EE was hijacked.

### Analysis

The EJBCA issuer docs say PKCS10 Enroll "creates or updates" an End Entity.
But "update" in a multi-tenant context should NOT mean:
- Moving an EE from one profile to another
- Allowing a credential with access to profile B to modify an EE in profile A
- Changing the authorization scope of existing certificates

The expected behavior should be:
- If EE username exists under a profile the caller has no access to → **reject**
- "Update" should mean: re-enroll within the same profile (new cert, same EE)
- Profile changes should require explicit admin action, not implicit via enrollment

### Security Implications

In a multi-tenant EJBCA deployment:
- **Tenant A's certificates can be hijacked by Tenant B** if they share a CN
- The original tenant loses visibility and management access to their certs
- No audit trail indicates the profile change (unless EJBCA audit logs capture it)
- SAN/DN constraints of the new profile may not match the original cert's attributes
- Certificate revocation by the original tenant becomes impossible

### Additional Concerns

- What happens if the second End Entity profile has different SAN DNS name
  constraints that don't match the first cert's SANs? The cert is now under
  a profile whose constraints it may violate.
- What about key algorithm restrictions? A cert issued under a profile
  allowing RSA-4096 could end up under a profile that only allows ECDSA.
- The "update" behavior means that PKCS10 Enroll is not idempotent in a
  multi-profile context — the result depends on which credential calls it
  last, not which credential owns the EE.

### Bugs Identified

1. **Authorization violation**: PKCS10 Enroll allows cross-profile EE
   modification without access checks on the source profile.
2. **Duplicate cert issuance**: Same CSR enrolled twice in the same second,
   producing two certs with identical timestamps — no deduplication.
3. **Cert visibility orphaning**: Cert issued under profile A becomes
   invisible to profile A's role when EE moves to profile B.
4. **No profile-change protection**: No mechanism to prevent or detect
   EE profile reassignment via enrollment.

### Recommendation

This should be reported to Keyfactor as a security issue. The fix should be
at the EJBCA level: PKCS10 Enroll must check whether the caller has access
to the EE's **current** profile before allowing any modification. If the EE
exists under a profile the caller cannot access, the request must be rejected
with a clear error message.

Until fixed, the only safe multi-tenant deployment requires **globally unique
EE usernames** (see section 18's deterministic hash proposal) to prevent
any possibility of cross-tenant username collision.


## 20. Ghost Certificates: Permanent Records After EE Deletion (2026-03-09)

### The Problem

After the two-step cleanup (revoke cert via per-cert API, then delete EE),
the certificate record persists in the EJBCA database. The EE is gone, but
the cert is still there — a "ghost."

### Observed Behavior

```
$ elt list4 --ee-profile 'Profile-X'
  → EE "d81f..." no longer listed (EE deleted ✓)

$ elt count
  → EE not counted (EE deleted ✓)

$ elt list4 --ee-username d81f59767d02aefd493cad79c6ab03a0
  → Cert still appears! Status: Revoked. EE Profile still shows.
```

### Root Cause

EJBCA stores certificates and End Entities in **separate database tables**.
Deleting an EE (`DELETE /v1/endentity/{name}`) removes the EE record only.
The certificate record in `CertificateData` is permanent — there is no
REST API endpoint to delete a certificate.

### Impact

1. **Ghost certs count toward license totals** — EJBCA Enterprise is
   licensed by total certificates. Accumulated ghost records inflate the
   count and the license cost.
2. **Ghost certs consume database space** — each cert record includes
   the full certificate, metadata, and indexes. At scale (thousands of
   renewals), this adds up.
3. **Ghost certs appear in global API counts** — the `/v2/certificate/count`
   endpoint includes them in the total, inflating the gap between
   "global total" and "certs tied to EEs."
4. **Ghost certs are findable** — a targeted cert search by serial or
   username will still find them, which can confuse operators.
5. **Ghost certs are NOT findable** via EE profile searches, `count`,
   or `list3`/`list4 --ee-profile` — so they're invisible to normal
   operations but lurk in the database.

### Certificate Deletion Options

1. **Database Maintenance Service** (Enterprise Edition only) — EJBCA's
   scheduled job that purges expired/revoked cert records after a
   configurable retention period. This is the official mechanism.
   Must be explicitly enabled in System Configuration.

2. **Direct database SQL** — `DELETE FROM CertificateData WHERE ...`
   Works but is unsupported, risky, and requires DB access that
   managed appliances may not expose.

3. **Accept the ghosts** — the revoked cert is on the CRL, the EE is
   gone, normal ELT queries don't show it. It's inert. This is the
   pragmatic approach until Database Maintenance Service runs.

### Commentary

Keyfactor's position that "you're not supposed to want to delete
certificates" conflates audit logs with artifacts. Certificate records
are data, not logs. Audit logs (which EJBCA maintains separately) are
the appropriate place for historical records. The inability to delete
cert records via the REST API — while the Database Maintenance Service
can do it on a schedule — is an artificial restriction, not a technical
one.

The fact that EJBCA Enterprise is licensed by total certificate count
creates a perverse incentive: accumulated ghost records from normal
cert-manager renewal cycles inflate the license count. In environments
with aggressive renewal schedules (hourly, daily), ghost certs accumulate
at the renewal rate multiplied by the certificate lifetime — potentially
thousands of records that serve no operational purpose but count toward
licensing.

### Recommendation

- Enable Database Maintenance Service immediately on all EJBCA instances
- Set retention period appropriate to compliance requirements
- Monitor global cert count vs EE-tied cert count as a ghost cert metric
- Request Keyfactor add a `DELETE /v1/certificate/{issuer}/{serial}`
  endpoint to the REST API for explicit cert record deletion


## 21. Database Maintenance Service Configuration (2026-03-09)

### Service Overview

Enterprise-only feature (since EJBCA 8.1). Polls the database and deletes
expired certificate records and old CRLs. Cleanup condition:

```
expireDate < (today - delayTime)
```

### Recommended Configuration

| Setting | Recommended | Default | Notes |
|---------|------------|---------|-------|
| CAs to Check | All CAs | (none) | Ghost certs from deleted EEs still reference their CA |
| Delay After Expiration | Minimum allowed by compliance | 30 days | DEV/test: 1 day |
| Delete Expired Certificates | true | true | |
| Delete Expired CRLs | true | true | Old CRLs accumulate too |
| Entries to delete per run | 1000-5000 | 100 | Increase for backlog; monitor DB load |

### Critical Prerequisite: Database Index

Create before enabling the service:
```sql
CREATE INDEX certificatedata_idx_exp ON CertificateData (expireDate);
```
Without this, every run does a full table scan.

### Certificate Status Lifecycle

| Code | Name | Set by | Meaning |
|------|------|--------|---------|
| 20 | ACTIVE | Enrollment | Valid certificate |
| 21 | NOTIFIED | Notification job | Active, expiry warning sent |
| 40 | REVOKED | Revocation API | Permanently revoked |
| 60 | ARCHIVED | CRL creation job | Expired cert, archived |

### THE GOTCHA: Revoked Certs with Long Lifetimes

The service deletes based on **expireDate**, not status. A revoked cert
with 3 years remaining validity won't be purged for 3 years + delay,
regardless of revocation status.

Impact on cleanup:

| Cleanup action | Cert status | When purged |
|---------------|-------------|-------------|
| Revoke + delete EE | 40 (REVOKED) | At original expiry + delay |
| Delete EE without revoke | 20 (ACTIVE) | At original expiry + delay |
| Natural expiry + CRL job | 60 (ARCHIVED) | At expiry + delay |
| Do nothing (accumulation) | 20 (ACTIVE) | At expiry + delay |

For a 3-year cert revoked today: ghost record persists for ~3 years.
For a 47-day cert revoked today: ghost record purged in ~47 days + delay.

### DELETE WITHOUT REVOKE: Worst Case

Deleting an EE without revoking first creates an **active ghost**:
- Status stays 20 (ACTIVE) — the cert is technically valid
- Not on any CRL — relying parties consider it valid
- OCSP responds "good" if queried
- Database Maintenance Service eventually purges it at expiry + delay
- **But until then, it's a valid certificate with no owner**

**Always revoke before deleting the EE.**

### Recommendation: Short-Lived Certificates for cert-manager

For Kubernetes cert-manager environments, configure short-lived certificates
(e.g., 47 days for TLS ServerAuth). This provides multiple benefits:

1. **Faster garbage collection** — revoked/accumulated cert records are
   purged by Database Maintenance Service in weeks, not years.

2. **Smaller CRL impact** — revoked short-lived certs drop off the CRL
   quickly as they expire and get archived.

3. **Reduced accumulation damage** — even without Single Active Certificate
   Constraint, accumulated certs from renewals expire quickly. A 47-day
   cert with daily renewal accumulates ~47 active certs max, vs ~1095
   with a 3-year cert.

4. **Industry direction** — CA/B Forum, Apple, and Google are converging
   on shorter TLS certificate lifetimes (90 days → 47 days). Configuring
   this now aligns with where the industry is heading.

5. **cert-manager handles renewals automatically** — the short lifetime
   is invisible to applications. cert-manager renews before expiry,
   Kubernetes distributes the new cert to pods, no manual intervention.

6. **Reduced blast radius** — a compromised short-lived cert is valid
   for weeks, not years. Even without revocation, the exposure window
   is bounded.

The tradeoff is more frequent renewals (more EJBCA API load, more cert
records created per year), but with proper Single Active Certificate
Constraint and Database Maintenance Service, this is manageable.

**For internal IT security teams accustomed to 2-3 year certs:**
The old model (long-lived certs, manual renewal) works when humans manage
a small number of certificates. In an automated K8s environment with
hundreds or thousands of services, short-lived + auto-renewed is both
more secure and more operationally sound. The CA/B Forum agrees — the
industry is moving this direction regardless of PKI vendor choice.


## 22. cert-manager "duration" Ignored by EJBCA (2026-03-10)

### The Problem

cert-manager Certificate YAML specifies `duration: 1h`, but the issued
certificate has 47-day validity (matching the EJBCA Certificate Profile).
The `duration` field is silently ignored.

### Observed

```yaml
spec:
  duration: 1h
  renewBefore: 5m
```

Resulted in:
```
Not Before: Mar 10 09:17:20 2026 GMT
Not After : Apr 26 09:17:19 2026 GMT     # 47 days, not 1 hour
```

### Root Cause

The `duration` field in the cert-manager Certificate YAML is a *request*.
The EJBCA Certificate Profile enforces its own validity setting. The
EJBCA issuer either doesn't pass the requested validity to the PKCS10
Enroll endpoint, or EJBCA ignores it even with "Allow Validity Override"
enabled in the Certificate Profile.

Confirmed by Keyfactor vendor contact (A.H., January 2026):
"The 'duration' setting in a certificate definition does not look to
have any effect, even with 'Allow Validity Override' enabled."

### Impact on renewBefore

Since EJBCA controls the actual cert lifetime, `renewBefore` must be
calculated relative to the EJBCA-issued validity, not the requested
duration. For a 47-day cert:

```yaml
# WRONG — expects 1h cert, renewal never triggers (47 days away)
duration: 1h
renewBefore: 5m

# CORRECT — matches actual 47-day validity
duration: 1128h             # 47 days (informational, EJBCA ignores it)
renewBefore: 1127h          # renew ~1 hour after issuance (for testing)

# ALSO WORKS — percentage-based
renewBeforePercentage: 99   # renew after 1% of lifetime (~11 hours)
```

### Tracking

- github.com/Keyfactor/ejbca-cert-manager-issuer/issues/128
- github.com/Keyfactor/ejbca-ce/discussions/1014

An EJBCA core developer has acknowledged the issue. Fix timeline unclear.


## 23. Single Active Certificate Constraint: Confirmed Working (2026-03-10)

### Setup

- Certificate Profile: Single Active Cert: checked
- cert-manager: `rotationPolicy: Always` (new key each renewal)
- Test: manual `cmctl renew` triggers

### Result

After each renewal, the previous cert is automatically revoked:
```
   #  S  Serial    Not Before                Not After                 CN
----  -  --------  ------------------------  ------------------------  ----------------------
   1  A  2a9ba...  Mar 10 15:07:32 2026 GMT  Apr 26 15:07:31 2026 GMT  JohnB-6 rapid renewals
   2  R  49b0f...  Mar 10 15:06:56 2026 GMT  Apr 26 15:06:55 2026 GMT  JohnB-6 rapid renewals
   3  R  3de50...  Mar 10 15:05:48 2026 GMT  Apr 26 15:05:47 2026 GMT  JohnB-6 rapid renewals
   4  R  2f4ca...  Mar 10 15:05:48 2026 GMT  Apr 26 15:05:47 2026 GMT  JohnB-6 rapid renewals
   5  R  2a87b...  Mar 10 09:17:20 2026 GMT  Apr 26 09:17:19 2026 GMT  JohnB-6 rapid renewals
```

Only the newest cert (#1) is active. All previous certs auto-revoked.

### Anomaly: Duplicate Issuance on First Renewal

Certs #3 and #4 have identical NotBefore timestamps (same second).
This appears to be the same duplicate issuance race condition observed
in section 19 (cross-profile bug). One cert was immediately revoked by
Single Active Cert constraint. Likely a one-time artifact of the config
change (first renewal after enabling the constraint). Subsequent renewals
produced single certs as expected.

### Conclusion

Single Active Cert constraint is the recommended setting for cert-manager
profiles. It provides automatic cleanup of previous certs on renewal,
preventing unbounded cert accumulation per EE. Combined with 47-day
validity and Database Maintenance Service, this is the complete lifecycle:

1. cert-manager renews → new cert issued
2. Single Active Cert → old cert auto-revoked
3. Old cert expires after 47 days
4. Database Maintenance Service → cert record purged after delay
