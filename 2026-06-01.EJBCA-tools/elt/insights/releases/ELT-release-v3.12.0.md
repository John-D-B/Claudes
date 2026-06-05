# ELT-release-v3.12.0.md

ejbca-lifecycle-tool.py v3.12.0 Release Notes

**Author:**  John Buehrer (JohnB), with AI pair-programming support by Anthropic Claude
<br/>
**Date:**  2026-04-01

---

## Summary

v3.12.0 is a quality and usability release. The main theme is **consistent
output banners** across all commands: every report now shows the same
header structure regardless of which filters are applied, making archived
output reliably self-describing.

Previous releases (v1.0.0 through v3.11.0) were internal development
iterations and are not separately documented.


## What Was Built

### Consistent Report Banners (list and count)

All `list` and `count` commands now share a single banner template,
produced by a new `_print_list_banner()` helper function. Previously,
each detail level (d1–d4) had its own banner code, and the single-EE
path (when `-ee-username` was supplied) produced a different title and
omitted the `Generated:` timestamp.

Every report now always shows:

```
==============================================================================
<command title>:  list -dN
EE Profile:    <name>           ← if -ee-profile specified
EE Username:   <name>           ← if -ee-username specified
Cert Serial:   <value>          ← if -cert-serial specified
Cert CN:       <value>          ← if -cert-cn specified
K8s Status:    <value>          ← if -k8s-status specified
K8s Compare:   enabled          ← if -k8s-compare specified
Generated:     <ISO 8601 UTC>   ← always
Host:          <host>:<port>    ← always
==============================================================================
```

The `Host:` line is new in this release (see below).

### Host Line in All Report Banners

`Host: <ejbca_host>:<port>` is now printed in every report banner,
immediately after `Generated:`. This makes archived reports
unambiguously traceable to the EJBCA environment that produced them —
important in multi-environment deployments (DEV, TEST, REF, PROD).

### Generated Timestamp in count

The `count` command was missing the `Generated:` timestamp that all
`list` commands had. This is now consistent.


## Files Changed

| File | Change |
|------|--------|
| `ejbca-lifecycle-tool.py` | New `_print_list_banner()` helper; `Host:` in banners; `Generated:` in count |


## Handover

### Current State

v3.12.0. Single-file tool, no build step required.

### Open Items / Next Session

- Test consistent banner output across all detail levels and filter combinations
- Claude Code session pending: test ELT cleanup with read-only certificate
  (fix requests should fail cleanly with a clear EJBCA error message)

### Delivery

    ejbca-lifecycle-tool.py   (single file, no installation required)
    requirements.txt          (for pip-audit; core deps: requests, urllib3)
