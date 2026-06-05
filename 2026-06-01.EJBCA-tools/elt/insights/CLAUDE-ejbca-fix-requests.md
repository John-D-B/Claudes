# EJBCA Fix Requests for Kubernetes cert-manager Integration

**Author:** John Buehrer (JohnB), with AI pair-programming support by Anthropic Claude
<br/>
**Date:** 2026-03-19

**Product:** EJBCA Enterprise / Software Appliance, versions 9.2.3 to 9.4.2
<br/>
**Component:** REST API — End Entity Search; EJBCA Issuer for cert-manager
<br/>
**Environment:** Kubernetes — Microk8s (as per vendor tutorial) and Red Hat OpenShift (RHOS)
<br/>
**Integration:** cert-manager with EJBCA Issuer for cert-manager
<br/>
**Severity:** Medium — functional gaps requiring workarounds
<br/>
**API Reference:** [EJBCA OpenAPI Specification]( https://docs.keyfactor.com/ejbca/latest/open-api-specification ) → `openapi.json` (downloadable from that page)

---

## Summary

These issues were found in the EJBCA REST API related to End Entity search and profile discovery, plus a minor data quality issue in the authorized profiles endpoint. Together they make it impossible to determine which End Entity Profile an entity belongs to using only the REST API.

A separate fix for the cert-manager issuer — already in review — addresses the long-standing problem of certificate duration being silently ignored by EJBCA.

Fix requests follow the issue descriptions.

---

## Issues Found

### 10. Documentation gap: `END_ENTITY_PROFILE` criterion requires profile name, not ID

**Status: Clarified 2026-03-19** — vendor confirmed; original report was incorrect.

The `END_ENTITY_PROFILE` search criterion works correctly on the v2 endpoint when the **profile name** (string) is supplied as the value. Using the numeric profile ID — which the `GET /v2/endentity/profiles/authorized/` endpoint returns and which appears in the Admin GUI — results in HTTP 400. This behaviour is not documented in the API reference.

Additionally, the v1 endpoint silently accepts the criterion but returns 0 entities regardless of the value supplied (name or ID). This silent failure is also undocumented.

**Confirmed across EJBCA versions 9.2.3, 9.3.3, and 9.4.2** using `elt ping -v`, which auto-fetches the first authorised profile name and tests both endpoints.

**Original error (using numeric ID):**
```json
{ "error_code": 400, "error_message": "Invalid search criteria content, unknown end entity profile." }
```

**Working example (using profile name, v2 only):**
```json
{
  "max_number_of_results": 100,
  "current_page": 1,
  "criteria": [
    { "property": "END_ENTITY_PROFILE", "value": "My-EE-Profile-Name", "operation": "EQUAL" }
  ],
  "sort_operation": { "property": "USERNAME", "operation": "ASC" }
}
```

**Remaining documentation gaps:**
- The API reference should state that profile name, not ID, is required for `END_ENTITY_PROFILE` in the End Entity search endpoint. Note: the certificate search endpoint (`SearchCertificateCriteriaRestRequest` in `openapi.json`) does already document this correctly: *"END_ENTITY_PROFILE, CERTIFICATE_PROFILE, CA — exact match of the name"* — the equivalent description is simply missing from the End Entity search schema.
- The v1 silent-zero behaviour should be documented or fixed
- The `GET /v2/endentity/profiles/authorized/` response should clarify which field to use as the search criterion value

---

### 11. Issue: Search response omits profile information

The End Entity search response (both v1 and v2) contains only 7 fields per entity: `username`, `dn`, `subject_alt_name`, `email`, `status`, `token`, `extension_data`.

Notably absent: `end_entity_profile_name`, `certificate_profile_name`, `ca_name`.

These fields are part of the EJBCA data model — the `POST /v1/endentity` (create) and `POST /v1/endentity/edit` (edit) endpoints both accept and store them. The search endpoint simply does not return them.

**Impact:** Even if issue 10 were resolved, a search without profile filtering would return entities with no way to identify their profile affiliation from the response alone.

Adding `end_entity_profile_name`, `certificate_profile_name`, and `ca_name` to the search response would resolve issues 10, 11, and 12 in a single change, since clients could then filter client-side on the returned profile name. This is the highest-impact fix.

---

### 12. Issue: No endpoint to retrieve individual End Entity details

The REST API provides no way to retrieve the full details of a single End Entity by username. The `/v1/endentity/{endentity_name}` path parameter only exists for `DELETE` and `PUT .../revoke`. There is no `GET` counterpart.

As confirmed in the Swagger UI at `/ejbca/doc/swagger-ui/`, the v1 End Entity endpoints are:

- `POST /v1/endentity` — Create
- `DELETE /v1/endentity/{endentity_name}` — Delete
- `POST /v1/endentity/edit` — Edit
- `PUT /v1/endentity/{endentity_name}/revoke` — Revoke
- `POST /v1/endentity/search` — Search
- `POST /v1/endentity/{endentity_name}/setstatus` — Set status
- `GET /v1/endentity/status` — API health check

And v2 adds:

- `GET /v2/endentity/profiles/authorized` — List authorised profiles
- `GET /v2/endentity/profile/{endentity_profile_name}` — Get profile content
- `POST /v2/endentity/search` — Search (with sorting)
- `GET /v2/endentity/status` — API health check

Neither version provides a read-by-username endpoint.

**Note:** if issue 11 were fixed (profile fields added to search results), this issue would become lower priority. A `GET /v1/endentity/{endentity_name}` would still be valuable for single-entity lookups and tooling, but the search endpoint is the higher-impact fix.

**Relationship between issues 10–12:** these are interconnected. Any *one* of the following fixes would unblock REST API users from identifying per-entity profile associations:
- **Fix 10** (search filter works) → clients can scope searches to a single profile.
- **Fix 11** (search returns profile fields) → clients get profile info in every result. **This is the simplest and highest-impact fix.**
- **Fix 12** (add per-entity GET) → clients can look up individual entities, but at O(n) cost for bulk operations.

---

### 13. Issue: Typos in response field names

Two field name typos across different endpoints:

**13a.** `GET /v2/endentity/profiles/authorized/` returns JSON with key `end_entitie_profiles` (missing "y" — should be `end_entity_profiles`).

**13b.** `POST /v2/certificate/search` returns certificate records with the field `udpateTime` (letters transposed — should be `updateTime`). Confirmed present verbatim in the official `openapi.json` spec under `CertificateRestResponseV2`, meaning both the runtime response and the published API reference contain the typo.

**Impact:** Low — clients must accommodate both typos. Fixing them in a future release would be a breaking change for clients that have already adapted to the misspellings; a deprecation strategy may be needed (e.g. return both old and corrected key names temporarily).

---

## Fix Requests

### 20. Fix (pending review): EJBCA Issuer for cert-manager — certificate duration ignored by EJBCA

The `duration` field in a Kubernetes `Certificate` resource specifies the desired certificate lifetime. The cert-manager EJBCA issuer does not pass this value to EJBCA, so the Certificate Profile validity always takes precedence — silently. This prevents cert-manager users from requesting different lifetimes per Certificate resource; a separate EJBCA Certificate Profile is required for each distinct duration, causing profile proliferation in multi-tenant environments.

A fix has been developed and submitted for review:

- **Pull request:** [PR #129 — Pass requested duration to EJBCA via `end_time` field]( https://github.com/Keyfactor/ejbca-cert-manager-issuer/pull/129 )
- **Issue:** [#128 — Certificate duration/validity not honoured]( https://github.com/Keyfactor/ejbca-cert-manager-issuer/issues/128 )
- **Community discussion:** [EJBCA CE Discussion #1014]( https://github.com/Keyfactor/ejbca-ce/discussions/1014 )

The fix uses the `end_time` field in the PKCS10 Enroll REST endpoint. This field is present in the official `openapi.json` spec under `EnrollCertificateRestRequest` (description: *"Valid end time — ISO 8601 Date string"*), but is not mentioned in the narrative REST interface documentation, making it effectively invisible to integrators. It is gated on "Allow Validity Override" being enabled in the Certificate Profile. EJBCA enforces the profile maximum as an upper bound, so the Certificate Profile remains the policy control; the issuer simply passes the requested duration when provided.

---

### 21. Request: Provide systematic enumeration and remediation of ghost certs and obsolete End Entities

In active Kubernetes environments, EJBCA can accumulate thousands of certificate records and hundreds of orphaned End Entities — volumes that make any GUI-based investigation impractical. The EJBCA REST API provides no convenient or systematic way to enumerate accumulated ghost certificate records (cert records that outlive their deleted End Entity) or obsolete End Entities (EEs no longer backed by an active workload). Bulk remediation — identifying candidates and revoking or deleting them — requires a series of cross-referencing queries across the EE and certificate search endpoints, with client-side correlation and pagination. There is no batch delete endpoint for certificate records (see fix request 25) and no query filter to identify orphaned or ghost records directly.

This gap is addressed in practice by `ejbca-lifecycle-tool.py`, developed as part of this investigation. The tool performs the necessary cross-referencing and provides commands for systematic enumeration (`elt list3`, `elt list4`, `elt count`, `elt count -ghosts`) and batch remediation (`elt cleanup`, `elt cleanup --delete-ee`). It demonstrates that the underlying data is available in the API — the missing piece is an efficient, first-class query and action surface for lifecycle management at scale.

---

### 22. Request: Document `END_ENTITY_PROFILE` criterion behaviour (see issue 10)

The API reference should explicitly state that `END_ENTITY_PROFILE` requires the profile **name** (string), not the numeric ID. The certificate search schema in `openapi.json` already does this correctly (`SearchCertificateCriteriaRestRequest`: *"exact match of the name"*); the same language should be added to the End Entity search schema (`SearchEndEntityCriteriaRestRequestV2`). The `GET /v2/endentity/profiles/authorized/` response should also indicate which field to use as the criterion value. Additionally, the v1 endpoint's silent-zero behaviour for this criterion should be documented or corrected.

---

### 23. Request: Include profile fields in search results (see issue 11)

Add `end_entity_profile_name`, `certificate_profile_name`, and `ca_name` to the End Entity search response (v1 and v2). This is the highest-impact single fix — it resolves the practical problem of issues 10, 11, and 12 in one change.

---

### 24. Request: Add `GET /v1/endentity/{endentity_name}` (see issue 12)

Add a read-by-username endpoint as the natural counterpart to the existing create, edit, delete, and revoke endpoints. This enables single-entity lookups without a full search, and is the expected REST API pattern for a resource that already supports write-by-name operations.

---

### 25. Request: Fix JSON key typos (see issue 13)

Correct `end_entitie_profiles` → `end_entity_profiles` and `udpateTime` → `updateTime`, with appropriate backward compatibility handling (e.g. return both old and corrected key names for one release cycle).

---

### 26. Request: Add `DELETE /v1/certificate/{issuer_dn}/{serial}` (new)

Currently there is no REST API endpoint to delete an individual certificate record. Revocation (`PUT /v1/certificate/{issuer_dn}/{serial}/revoke`) is the furthest the API goes. The Database Maintenance Service can purge expired records, but revoked-but-unexpired records cannot be removed via the API — only by direct database access or the EJBCA admin CLI (unavailable on the Software Appliance).

Adding a delete endpoint would allow tools like `ejbca-lifecycle-tool.py` to clean up ghost certificate records using permissions already within the RA Administrator role template, without requiring elevated or out-of-band access.

**Proposed location:** &nbsp; 2026-05-20<br/>
This endpoint should be added as a new `@DELETE` method on `CertificateRestResource` — the CE-shipped class that already hosts `PUT /v1/certificate/{issuer_dn}/{serial}/revoke` — using the same path-parameter shape and the same authorization model. Implementation also requires a companion `removeCertificate(issuerDn, serialNumber)` method on `CertificateStoreSession` in `cesecore-ejb-interface`, since no per-record certificate delete exists in the EJB layer today.

**Edition placement:** &nbsp; 2026-05-20<br/>
Because `CertificateRestResource` is in the CE distribution, fix 26 should ship in CE alongside the existing `revoke` endpoint — both endpoints are lifecycle operations on the same resource. The vendor's "Management REST API" Enterprise-only gate (as documented at [ejbca.org/community-vs-enterprise](https://www.ejbca.org/community-vs-enterprise/)) applies specifically to the **End Entity** REST resource classes (`EndEntityRestResource`, `EndEntityRestResourceV2`), which are simply not shipped in CE; the certificate REST surface is. From an Enterprise user's perspective the "Enrollment REST API" vs "Management REST API" distinction is invisible — the REST API is just present, no product-family introspection required. The categorization becomes visible only when targeting CE or when accepting upstream contributions, where the placement on a CE-shipped resource class is what determines edition reach.

---

### 27. Request: Add "Delete Revoked Certificates" option to Database Maintenance Worker

The Database Maintenance Worker currently supports deletion of *expired* certificate records and expired CRLs. It has no facility to delete *revoked-but-unexpired* certificate records, which are the primary source of database accumulation in environments using the Single Active Certificate Constraint (which revokes previous certificates with reason `SUPERSEDED` on each renewal).

**Proposed addition to the Database Maintenance Worker configuration:**

- **Delete Revoked Certificates:** `[ ] Use` (unchecked by default)
- **Selector: Revoke Reasons** — one or more revocation reasons can be selected (e.g. `SUPERSEDED`, `KEY_COMPROMISE`, `CESSATION_OF_OPERATION`); defaults to `SUPERSEDED` when Use is checked

This pairs naturally with the Single Active Certificate Constraint in Certificate Profiles: that feature revokes previous certs with reason `SUPERSEDED`; this feature would then purge those records on the next DBMS run, without waiting for `notAfter`. Together they form a complete automated lifecycle: issue → auto-revoke previous (Single Active) → purge revoked (DBMS) → no accumulation.

This would also eliminate most ghost certificate records — the cert records that outlive a deleted End Entity. In the recommended cleanup workflow (revoke certs before deleting EE), the surviving cert records are revoked with reason `SUPERSEDED`, and would be caught by this new DBMS option automatically. This is a simpler operational solution than a new REST API delete endpoint (fix request 26), and requires no change to client tooling.


---

## Workarounds (Current)

In the absence of fixes for issues 10–12, the current workaround used by `ejbca-lifecycle-tool.py`:

1. Use `GET /v2/endentity/profiles/authorized/` to obtain the profile name (accommodating the `end_entitie_profiles` typo from issue 13a).
2. Search entities using `END_ENTITY_PROFILE` criterion with the profile name via `POST /v2/endentity/search` (v2 only — v1 silently returns zero results).
   - Fallback: if no profile filter is needed, iterate all `STATUS` values.
3. **Enrich with profile data via `POST /v2/certificate/search`** — the v2 certificate search endpoint returns `endEntityProfile`, `endEntityProfileId`, and `certificateProfile` per certificate. Cross-reference by `username` to fill in the missing profile fields.
4. Filter client-side by profile name using the enriched data.

This workaround is effective but relies on the certificate endpoint returning data that the End Entity endpoint should include natively. It also requires entities to have at least one issued certificate — entities with no certificates cannot have their profile determined this way.

**Note:** the v2 certificate search endpoint requires `pagination` and `sort` fields in the JSON body; without them it returns `total_certs` counts but an empty `certificates` array. This requirement is not documented.

---

## Context

These topics were discovered while building `ejbca-lifecycle-tool.py`, an End Entity lifecycle management tool for environments using EJBCA with the Kubernetes cert-manager EJBCA issuer. In this integration pattern, cert-manager users configure their Issuer resource with an `endEntityProfileName` (string) and never interact with the EJBCA Admin GUI — they need to query and manage End Entities by profile name through the REST API alone.
