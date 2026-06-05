# EJBCA tools

**Author:** John Buehrer (JohnB), with AI pair-programming support by Anthropic Claude<br/>
**Date:** 2026-06-01

A small bundle of Python tools for working with **EJBCA** — Keyfactor's<br/>
&nbsp; &nbsp; open-source PKI server — from outside the EJBCA admin GUI. Built around<br/>
&nbsp; &nbsp; concrete operational needs that arose during PR-work for the<br/>
&nbsp; &nbsp; **EJBCA-Issuer** (cert-manager external issuer), the **DBMS Reaper**, and<br/>
&nbsp; &nbsp; the **REST-API Certificate Delete** features in EJBCA-CE and EJBCA-EE.

The tools work standalone — each does one well-scoped job — and compose<br/>
&nbsp; &nbsp; cleanly: deploy a working stack, drive operations against it, inspect the<br/>
&nbsp; &nbsp; resulting certificates.

## What's in here

| Directory | Tool | What it does |
|---|---|---|
| [`dek/`](./dek/) | **`deploy_ejbca_k8s.py`** | Deploys `cert-manager` and the EJBCA cert-manager-issuer into a Kubernetes cluster, then issues a test certificate end-to-end against an EJBCA backend. Idempotent re-implementation of Keyfactor's *"Use EJBCA with cert-manager"* tutorial as a CLI tool. |
| [`elt/`](./elt/) | **`ejbca-lifecycle-tool.py`** (ELT) | Direct EJBCA REST / SOAP client for listing, enrolling, revoking, and reaping End Entities and certificates. Useful as a quick CLI alternative to the EJBCA admin GUI. |
| [`cg/`](./cg/) | **`cert-grep.py`** | Standalone X.509 pretty-printer. Reads PEM or DER from stdin or by path, emits chosen `summary_N` views of the cert internals. A friendlier alternative to `openssl x509 -text -noout`. |
| [`bin/`](./bin/) | (symlinks) | Single flat namespace for adding the tools to your `$PATH`. |

## Getting started

See [`bin/README.md`](./bin/) for the full install + smoke-test recipe.<br/>
&nbsp; &nbsp; In short: clone the repo, add `bin/` to your `$PATH`, run<br/>
&nbsp; &nbsp; `pip install -r` for each tool's `requirements.txt`, and confirm with<br/>
&nbsp; &nbsp; `--version`.

Each tool also has its own per-tool README in its source directory<br/>
&nbsp; &nbsp; (`dek/README-deploy-ejbca-k8s.md`, `elt/README-elt.md`,<br/>
&nbsp; &nbsp; `cg/README-cert-grep.md`) with longer-form documentation, usage<br/>
&nbsp; &nbsp; examples, and design notes.

## Why these tools exist

EJBCA is powerful and well-engineered, but its operational story leans hard<br/>
&nbsp; &nbsp; on the admin GUI and on long *"click here, click there"* tutorials.<br/>
&nbsp; &nbsp; That's fine for first-time exploration; it stops being fine when you<br/>
&nbsp; &nbsp; need to reproduce a deployment, exercise an edge case, test a fix,<br/>
&nbsp; &nbsp; or hand a working setup to a colleague.

These tools give you a tangible CLI handle into reproducible EJBCA work —<br/>
&nbsp; &nbsp; the kind of thing the vendor probably *should* supply but doesn't.<br/>
&nbsp; &nbsp; They cover the gap encountered repeatedly during contract work and<br/>
&nbsp; &nbsp; PR-driven testing, polished enough to share rather than leaving each<br/>
&nbsp; &nbsp; user to re-discover the same workarounds.

## Status

The tools are actively maintained alongside ongoing PR work for EJBCA-CE<br/>
&nbsp; &nbsp; and EJBCA-EE. The dated directory name (`2026-06-01.EJBCA-tools/`)<br/>
&nbsp; &nbsp; pins this published snapshot; later iterations may live alongside it<br/>
&nbsp; &nbsp; under their own dated subdirectories without breaking inbound links.

Issues, suggestions, and contributions are welcome via the parent<br/>
&nbsp; &nbsp; [`John-D-B/Claudes`](https://github.com/John-D-B/Claudes) repo.
