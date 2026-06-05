# ELT Cleanup Test Guide

**Quick reference** for testing the `elt cleanup` commands.
<br/>
Always test in **DEV** first.
<br/>
<br/>
**Author:** John Buehrer (JohnB), with AI pair-programming support by Anthropic Claude
<br/>
**Date:** 2026-03-08

---

## Cleanup Strategy Summary

### Target Selection

**Mode 1: `--k8s-compare` (recommended)**
- Runs `kubectl get certificates --all-namespaces -o json`
- Builds identity set from each Certificate's: commonName, dnsNames, resource name
- Compares each EJBCA EE username (and CN from DN) against this set
- EEs NOT found in K8s → orphans → targeted for cleanup
- EEs found in K8s → left alone

**Mode 2: Without `--k8s-compare` (dangerous)**
- Operates on ALL matching EEs
- Requires `--all-matching` as safety gate
- Use case: clearing out a test profile entirely

### Three Cleanup Actions

| Flags | Action | CRL/OCSP Impact |
|-------|--------|-----------------|
| *(default)* | Revoke all certs under EE (reason: SUPERSEDED) | Yes — certs on CRL |
| `--delete-after-revoke` | Revoke, then delete EE record | Yes — certs on CRL, EE gone |
| `--delete-only` | Delete EE record, skip revocation | None — certs valid until expiry |

### Safety Layers

- **Dry-run by default** — without `--confirm`, only shows what *would* happen
- `--ee-profile` narrows scope to one profile
- `--all-matching` required without `--k8s-compare`

---

## Test Sequence

### Step 1: Verify visibility before changes

```bash
# Baseline — save outputs for comparison
elt list3 --ee-profile "Test-Profile" -F | tee qq-ENV.list3-before.txt
elt count                                | tee qq-ENV.count-before.txt
```

### Step 2: Dry run (safe — no changes)

```bash
# With K8s cross-reference
elt cleanup --ee-profile "Test-Profile" --k8s-compare

# Without K8s — target all EEs in profile
elt cleanup --ee-profile "Test-Profile" --delete-only --all-matching
```

Review the target list. Does it look right?

### Step 3: Execute (destructive)

```bash
# Option A: Delete only (no CRL/OCSP overhead)
elt cleanup --ee-profile "Test-Profile" --k8s-compare --delete-only --confirm

# Option B: Revoke + delete
elt cleanup --ee-profile "Test-Profile" --k8s-compare --delete-after-revoke --confirm

# Option C: Revoke only (keep EE records)
elt cleanup --ee-profile "Test-Profile" --k8s-compare --confirm
```

### Step 4: Verify after changes

```bash
elt list3 --ee-profile "Test-Profile" -F | tee qq-ENV.list3-after.txt
elt count                                | tee qq-ENV.count-after.txt

# Compare
diff qq-ENV.list3-before.txt qq-ENV.list3-after.txt
diff qq-ENV.count-before.txt qq-ENV.count-after.txt
```

---

## Open Questions to Test

- [ ] Does `--delete-only` succeed when EE has active (unrevoked) certs?
- [ ] After `--delete-only`, do orphaned cert records remain in the DB?
- [ ] After `--delete-only`, does `elt count` show a lower global total?
- [ ] Does `--delete-after-revoke` leave cert records (revoked) in the DB?
- [ ] What does the EJBCA Admin GUI show after each operation?

---

## Quick Reference: Related Commands

```bash
elt list1                                  # EE profiles
elt list3 --ee-profile "Profile" -F        # EE inventory with cert counts
elt list4 --ee-username "username"         # All certs for one EE
elt count                                  # Executive summary
```
