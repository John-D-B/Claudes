# EJBCA Configuration Checklist for cert-manager Integration

**Author:** John Buehrer (JohnB), with AI pair-programming support by Anthropic Claude
<br/>
**Date:** 2026-03-18

---

### CA Configuration
*(applies only to the Issuing CA referenced by the End Entity Profile)*

- [ ] **Enforce unique public keys** — **unchecked** (cert-manager generates new keys each renewal with `rotationPolicy: Always`)
- [ ] **Enforce unique DN** — **unchecked** (same CN reused across renewals)
- [ ] **Finish User** — **checked** (password not blanked for User Generated tokens)

### Certificate Profile *(Type: End Entity)*
*(applies only to the Leaf certificate profile referenced by the End Entity Profile)*

- [ ] Key algorithm and size match the cert-manager Certificate spec
- [ ] **Validity** — **47 days** recommended for cert-manager-managed certs (short-lived, auto-renewed)
- [ ] **Allow Validity Override** — **checked** (needed once the cert-manager issuer passes requested validity to EJBCA)
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
*(This section covers the REST API access certificate used by `ejbca-lifecycle-tool.py` for minimal, read-only access. cert-manager requires a separate role with enrolment permissions.)*

- [ ] RA Administrator role created with appropriate access
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
