# ELT-release-v3.13.0.md

ejbca-lifecycle-tool.py v3.13.0 Release Notes

**Author:**  John Buehrer (JohnB), with AI pair-programming support by Anthropic Claude
<br/>
**Date:**  2026-04-02

---

## Summary

v3.13.0 adds certificate list truncation in `list4`. In environments
with high-frequency cert-manager renewals, a single End Entity can
accumulate thousands of revoked certificate records. Without truncation,
`elt list4` on such an EE would dump thousands of rows without warning —
not useful, and potentially alarming.


## What Was Built

### Certificate List Truncation in list4 (default: 10 rows)

`_print_ee_cert_table()` now limits the displayed certificates to
**10 rows by default**. When more exist, a message is appended:

```
  ... 1575 more — use -F to see the full list
```

Applies to both output formats:
- `cert_detail=0` — compact table (default)
- `cert_detail>=1` — block format (`-ci1`, `-ci2`)

The full list is shown when `-F` is passed, which was already supported
for EE-level truncation in bulk list mode — so the flag behaviour is
now consistent throughout `list4`.

The truncation threshold is defined as a named constant
`CERT_DISPLAY_LIMIT = 10` inside `_print_ee_cert_table()`, making
it easy to adjust in future.


## Files Changed

| File | Change |
|------|--------|
| `ejbca-lifecycle-tool.py` | Cert list truncation at 10 in `_print_ee_cert_table()`; `-F` passes through to all call sites |


## Handover

### Current State

v3.13.0. Single-file tool, no build step required.

### Open Items / Next Session

- Test truncation output on REF mega-EE ("Renewal Hourly", ~1585 certs)
- Confirm `-F` overrides truncation correctly in all code paths
- Claude Code session pending: test ELT cleanup with read-only certificate
