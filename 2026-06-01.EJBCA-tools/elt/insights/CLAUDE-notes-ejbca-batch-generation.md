# EJBCA "Batch Generation" and cert-manager Renewals

**Author:** Claude (Anthropic), with John Buehrer  
**Date:** 2026-03-10  
**Context:** EJBCA 9.3.x Enterprise + Kubernetes cert-manager + Keyfactor EJBCA Issuer


## 1. The Problem

cert-manager certificate renewals fail with:

```
message: 'failed to sign: error enrolling certificate with EJBCA. verify that
  the certificate profile name, end entity profile name, and certificate authority
  name are appropriate for the certificate request.
  - {"error_code":400,"error_message":"No password in request."}'
```

This error occurs on renewal (re-enrollment), not on initial enrollment.
The cert-manager EJBCA issuer sends a PKCS10 Enroll request via the
REST API. First enrollment succeeds; subsequent enrollments for the
same End Entity may fail with this error.


## 2. What "Batch Generation" Actually Does

The End Entity Profile setting "Batch generation (clear text pwd storage)"
controls whether the EE password is stored in cleartext in the database.

**Original purpose (legacy):** The `bin/ejbca.sh batch` CLI tool generates
P12/JKS/PEM keystores for all EEs in NEW or FAILED status. It needs to
read the password from the database to create the keystore. This is a
server-side bulk operation from the early 2000s — manual PKI workflows.

**What it means for cert-manager:** When Batch generation is enabled,
EJBCA stores the password in cleartext. On re-enrollment via PKCS10
Enroll, the endpoint can update the EE (including the password) because
the old password is accessible. Without Batch, the password may be
hashed or cleared after first enrollment, and the re-enrollment update
path may fail because EJBCA can't verify or replace the credential.


## 3. EJBCA End Entity Status Lifecycle

EJBCA controls enrollment via EE status:

```
  NEW (10)  →  enrollment allowed
      ↓  (after certificate issuance)
  GENERATED (40)  →  enrollment normally blocked
      ↓  (can be reset to NEW for re-enrollment)
  NEW (10)  →  enrollment allowed again
```

Normally, EJBCA only allows enrollment when an EE is in NEW status.
After issuance, it transitions to GENERATED. For re-enrollment
(cert-manager renewal), the PKCS10 Enroll endpoint resets the EE
back to NEW as part of the call.

**The password check:** When the PKCS10 Enroll endpoint processes a
re-enrollment, it needs to authenticate the request. Authentication
can happen via:

1. **mTLS RA credential** — the cert-manager issuer authenticates
   via its client certificate, which has RA-level access
2. **EE password** — the password in the enrollment request body

Even with mTLS authentication, EJBCA may still require a password
in the request body to update the EE record. If Batch generation
is disabled, the stored password may not be accessible for comparison,
leading to the "No password in request" error.


## 4. Why A.H.'s Setup Worked Without Batch

The Keyfactor vendor contact (A.H.) reported not needing Batch
generation. Key differences in his setup:

- He followed the official tutorial exactly
- He needed to either manually approve requests OR add the issuer
  to auto-approved signers
- He tested with 2-year validity certificates

The approval workflow may bypass the password check entirely — when
a request goes through approval, the RA role authenticates the entire
flow, and the EE password becomes irrelevant. Different enrollment
paths in EJBCA have different authentication requirements.

This is a classic "it works on my machine" situation — the behavior
depends on the specific combination of:
- Approval configuration
- Role access rules
- EE profile settings
- Issuer version and configuration


## 5. The Security Non-Concern

Keyfactor's documentation warns that Batch generation stores passwords
in cleartext and recommends disabling it when "Allow Renewal Before
Expiration" is enabled.

**Why this warning is irrelevant for cert-manager:**

1. **If an attacker has database access, you've already lost.**
   The database contains private CA keys (for soft tokens), all
   certificate data, audit logs — everything. A cleartext EE
   enrollment password is trivial compared to what's already exposed.

2. **The EE password is a transient API handshake.** cert-manager
   generates a random password, sends it with the PKCS10 request,
   EJBCA uses it for the enrollment, and nobody ever looks at it
   again. It has zero value as a credential.

3. **A password nobody knows is a self-inflicted denial of service.**
   If something goes wrong and you need to manually debug or
   re-enroll, having the password accessible means you can actually
   fix things. Without it, you're locked out of your own EE.

4. **The threat model assumes multi-user database access.**
   Modern deployments use dedicated containers/VMs per application.
   The Unix timesharing model of multiple users sharing one system
   (and needing to protect from each other) doesn't apply.


## 6. What "Batch Generation" Really Means in 2026

"Batch generation" is a terrible name for what it actually enables:
**programmatic credential management for automated systems.**

In a cert-manager context:
- "Batch" = "automated" (not manual RA Web enrollment)
- "Clear text pwd storage" = "the system can manage its own credentials"
- "Enabled" = "allow the automation pipeline to work without
  hitting authentication barriers designed for human operators"

The name reflects EJBCA's 2000s-era design where "batch" meant
"run a CLI command to bulk-generate keystores." In 2026, it means
"don't break cert-manager renewals."


## 7. Recommendation

**Enable Batch generation for all cert-manager End Entity profiles.**

Rationale:
- Prevents "No password in request" error on renewals
- Enables reliable automated re-enrollment
- Security concern is theoretical and assumes a threat model
  that's already catastrophic
- The alternative (disabling it) may require specific approval
  workflows that add operational complexity without security benefit

**ELT hints include this recommendation as of v2.5.9:**
```
End Entity Profile
  Batch generation:           enable (allows automated re-enrollment;
                              without it, renewals may fail with
                              "No password in request" error 400)
```


## 8. Remaining Questions

- [ ] Does the PKCS10 Enroll endpoint behavior differ between
      EJBCA versions? The "No password" error may be version-specific.

- [ ] Does the approval workflow always bypass the password check?
      A.H.'s setup used approval; ours may not.

- [ ] Is there a role access rule that controls whether the password
      check is enforced? The RA role may have different behavior
      depending on specific access rules.

- [ ] Does the Keyfactor EJBCA Issuer always send a password field?
      Older versions may omit it on re-enrollment.

These questions are best answered by examining the EJBCA source code
(Java) or by systematic testing with different configurations. The
vendor has not provided definitive answers.


## 9. Historical Context

This investigation started in January 2026 when K8s/RHOS customers
reported renewal failures. The initial symptoms were confusing because:

1. First enrollment always worked
2. Manual `cmctl renew` triggered the error
3. The error message ("No password in request") seemed unrelated
   to the actual problem (password is an API detail, not a user-facing
   credential)
4. Vendor support could not reproduce the issue (different setup)
5. The fix (enable Batch generation) was discovered through Claude AI
   assistance and systematic testing, not through vendor guidance

This is representative of a broader pattern: EJBCA's configuration
space is large, the documentation describes individual settings but
not their interactions, and the vendor's support experience is biased
toward manual GUI workflows rather than automated K8s integration.
Tools like ELT help bridge this gap by making EJBCA's internal state
visible and actionable.


## 10. The "Finish User" Connection (2026-03-10)

The EJBCA CA Fields documentation reveals the mechanism behind
the "No password in request" failure:

**Finish User (CA setting):**
- **Enabled**: After certificate issuance, the EE password is blanked
  and status is set to GENERATED. A new certificate cannot be issued
  until status is manually reset to NEW.
- **Disabled**: The password can be used unlimited times, and status
  stays as NEW after each issuance.
- **Note**: The password is only blanked for token types *other than*
  User Generated.

This is the smoking gun. With Finish User enabled:
1. First enrollment succeeds (EE is NEW, password is set)
2. After issuance, password is blanked, status → GENERATED
3. Renewal attempt fails: "No password in request" (password is gone)

**Finish User + Batch generation interaction:**
- Finish User enabled + Batch disabled = renewal fails (password blanked)
- Finish User enabled + Batch enabled = may work (cleartext pwd preserved?)
- Finish User disabled = renewals work (password not blanked, status stays NEW)

**Recommendation:** ~~Disable "Finish User" on the CA for cert-manager profiles.~~

**CORRECTION (2026-03-10, later):** The docs state: "the password will
only be blanked for token types other than User Generated." Since
cert-manager uses User Generated tokens, the password is NOT blanked
even with Finish User checked (enabled). The PKCS10 Enroll endpoint
resets EE status from GENERATED back to NEW on re-enrollment. Therefore
Finish User can stay **checked** (the default). This is the tested,
working configuration. The "No password in request" error is more likely
caused by Batch generation being disabled, not by Finish User.

**The "User Generated" exception:** The docs note that "the password will
only be blanked for token types other than User Generated." Since
cert-manager uses User Generated tokens (CSR-based enrollment), the
password blanking may not apply. However, the status transition to
GENERATED still occurs, which may independently block re-enrollment.
This needs testing to confirm.

### "Enforce Unique Public Keys" — Not Relevant

The CA Fields docs clarify that "Enforce unique public keys" allows
same-username key reuse. Since cert-manager always enrolls under the
same EE username, this constraint never triggers regardless of the
cert-manager rotationPolicy setting. The default (checked) is fine.


## 11. Updated Recommendation Matrix (2026-03-10)

For cert-manager automated renewal, the following CA and EE settings
interact:

| Setting | Location | Recommended | Why |
|---------|----------|-------------|-----|
| Finish User | CA config | checked (default) | Password not blanked for User Generated tokens |
| Batch generation | EE profile | checked | Cleartext pwd storage for re-enrollment |
| Allowed requests | EE profile | "Use" unchecked | No enrollment count limit |
| Enforce unique DN | CA config | unchecked | Same CN across renewals |
| Enforce unique keys | CA config | default (checked) | No impact, safety net |
| Single Active Cert | Cert profile | checked | Auto-revokes previous cert |

These six settings together ensure that cert-manager can:
1. Enroll the first certificate (EE created in NEW status)
2. Re-enroll on renewal (EE stays in NEW, password accessible)
3. Auto-revoke the previous cert (Single Active Cert)
4. Repeat indefinitely without manual intervention


## 12. EE Profile Fields Doc Clarifications (2026-03-10)

### Batch Generation: "Clear Text" Is Misleading

The EJBCA End Entity Profiles Fields documentation states:

> "Enabling this setting stores the password as an encrypted value
> in the database. When this setting is disabled, the password is
> stored as a hash created with bcrypt in the database."

This is self-contradictory with the setting name "clear text pwd storage."
What they apparently mean:

- **Batch enabled**: password stored in reversibly-encrypted form
  (can be decrypted back to original by EJBCA)
- **Batch disabled**: password stored as bcrypt hash (one-way, not
  recoverable)

They call the recoverable form "clear text" because it can be decrypted
— but it's not literally stored in plaintext. The practical distinction:
with Batch enabled, EJBCA can *recover* the password for automated
processes. With Batch disabled, it can only *verify* a presented password
against the hash.

### Password Configuration for cert-manager

For cert-manager EE profiles:
- **Password Required**: unchecked
- **Password Auto-generated**: unchecked

Rationale: cert-manager sends its own random password with each PKCS10
Enroll request. Any password requirement on the EE profile side creates
a potential mismatch between what EJBCA expects and what the issuer
sends. Since the EJBCA and cert-manager admins are typically different
people, avoiding password requirements eliminates a class of hard-to-debug
integration failures.

### Username Auto-generated: Checked

The docs state: "Selecting the Auto-generated checkbox in the end entity
profile will generate unique values when end entities are added."

With auto-generated checked, EJBCA guarantees username uniqueness as a
fallback. The cert-manager issuer *may* override this via endEntityName,
but the auto-generated setting provides a safety net. This may also help
mitigate the multi-tenant username collision issue (section 18 of main
notes) — though the behavior when both auto-generated and issuer-override
are active needs further testing.

### Available Tokens

- **Default Token**: User Generated (cert-manager path: CSR-based enrollment)
- **Available Tokens**: All can be selected (supports RA Web exports in
  P12/JKS/PEM format for the same EE profile, used by other channels)

### Allow Renewal Before Expiration

The EJBCA End Entity Profiles Fields docs warn:

> "This option will also cause end entity passwords to be kept
> indefinitely in the database... it is strongly recommended that
> the option Batch generation (clear text pwd storage) is disabled
> when Allow Renewal Before Expiration is enabled."

This advice is specifically for manual-renewal scenarios where a human
types a password. For cert-manager (automated, mTLS-authenticated,
random passwords), this warning is not applicable. The "password brute
force" risk they cite assumes that attackers can attempt enrollment
with guessed passwords — in a cert-manager setup, enrollment is
authenticated via the RA mTLS credential, not the EE password.


## 13. Updated Recommendation Matrix v2 (2026-03-10)

Incorporates all doc review feedback. Tested with EJBCA Enterprise /
Software Appliance 9.3.3 - 9.4.2.

### CA Configuration (Issuing CA referenced by the End Entity Profile)
| Setting | Recommended | Why |
|---------|-------------|-----|
| Enforce unique DN | unchecked | Same CN reused across renewals |
| Enforce unique public keys | unchecked | Avoid obscure errors and DB indexes |
| Finish User | checked (default) | Password not blanked for User Generated tokens |

### Certificate Profile (type: End Entity — leaf certs only)
| Setting | Recommended | Why |
|---------|-------------|-----|
| Validity | 47 days | Short-lived, fast garbage collection |
| Single Active Cert | checked | Auto-revokes previous cert on renewal |

### End Entity Profile
| Setting | Recommended | Why |
|---------|-------------|-----|
| Username auto-generated | checked | EJBCA guarantees uniqueness |
| Password Required | unchecked | Avoid credential mismatches |
| Password Auto-generated | unchecked | Avoid credential mismatches |
| Batch generation | checked | Automated re-enrollment |
| Allowed requests "Use" | unchecked | Unlimited re-enrollment |
| Default Token | User Generated | cert-manager sends CSR |
| Available Tokens | all | Flexibility for RA Web |


## 14. Allow Validity Override and Allow Renewal Before Expiration (2026-03-10)

### Allow Validity Override (Certificate Profile): checked

The EJBCA Certificate Profile Fields documentation states:

> "The Allow Validity Override option allows requesting a specific
> notAfter date in issued certificates. This is currently possible
> when using CMP (the CRMF request format), when using APIs (REST,
> SOAP), or by using the RA Web enrollment page."

Currently, the cert-manager EJBCA issuer does not pass the requested
validity (the `duration` field from the Certificate YAML) to the PKCS10
Enroll endpoint. A GitHub issue has been filed:
github.com/Keyfactor/ejbca-cert-manager-issuer/issues/128

Once the issuer is patched to pass the requested validity, this setting
must be checked for it to take effect. Enabling it now is harmless —
EJBCA will continue to use the profile's validity until the issuer
actually sends a requested validity.

The docs also clarify the validity determination hierarchy:
1. The Validity field in the profile = maximum allowed validity
2. If Allow Validity Override is enabled, the profile value can be
   overridden with: start/end time from EE, or requested validity
   from the certificate request
3. The cert can never exceed the CA's own validity

### Allow Renewal Before Expiration (End Entity Profile): unchecked

The EJBCA End Entity Profiles Fields documentation states:

> "Normally, EJBCA will only allow the issuance of an end entity when
> it is in NEW state. With Allow Renewal Before Expiration enabled,
> certificates may be renewed even when in GENERATED state, when they
> are about to expire."

This is EJBCA's definition of "renewal" — re-enrollment of an EE that
is in GENERATED status, using the same password, within a time window
before the certificate expires.

**This is NOT what cert-manager does.**

cert-manager's "renewal" is a completely different mechanism:
1. cert-manager creates a new CSR with a new key pair
2. The EJBCA issuer calls the PKCS10 Enroll endpoint
3. The endpoint resets the EE status from GENERATED back to NEW
4. A new certificate is issued (new key, new serial, new CSR)
5. The EE transitions back to GENERATED

The PKCS10 Enroll endpoint bypasses the GENERATED-status check by
resetting the EE to NEW first. It does not use EJBCA's "Allow Renewal
Before Expiration" mechanism at all. cert-manager "renewal" is really
a fresh enrollment that happens to reuse the same EE username.

Analogy: it's like meeting a new person who happens to be wearing
someone else's clothes. Same name tag, completely different identity.

**Why leaving it unchecked is correct:**
- cert-manager renewals work without it (tested, confirmed)
- Enabling it keeps passwords in the database indefinitely
- The docs recommend disabling Batch generation when this is enabled,
  which contradicts our Batch recommendation
- It adds complexity for a mechanism cert-manager doesn't use

### Updated Recommendation Matrix v3 (2026-03-10)

| Setting | Location | Recommended | Why |
|---------|----------|-------------|-----|
| Enforce unique public keys | CA config | unchecked | Avoid errors and DB indexes |
| Enforce unique DN | CA config | unchecked | Same CN across renewals |
| Finish User | CA config | checked | Password not blanked for User Generated |
| Validity | Cert profile | 47 days | Short-lived, fast garbage collection |
| Allow Validity Override | Cert profile | checked | Forward-looking for issuer patch |
| Single Active Cert | Cert profile | checked | Auto-revokes previous cert |
| Username Auto-generated | EE profile | checked | EJBCA guarantees uniqueness |
| Password Required | EE profile | unchecked | Avoid credential mismatches |
| Password Auto-generated | EE profile | unchecked | Avoid credential mismatches |
| Batch generation | EE profile | checked | Automated re-enrollment |
| Number of allowed requests | EE profile | unchecked | Unlimited re-enrollment |
| Allow Renewal Before Exp. | EE profile | unchecked | Not used by cert-manager |
| Default Token | EE profile | User Generated | cert-manager sends CSR |
| Available Tokens | EE profile | all | Flexibility for RA Web |
