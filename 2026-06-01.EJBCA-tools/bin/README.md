# `bin/` — entry points for the EJBCA tool bundle

This directory holds symlinks to the three publishable Python scripts in this<br/>
&nbsp; &nbsp; bundle. Add this directory to your `$PATH` and the tools are callable<br/>
&nbsp; &nbsp; by name; the symlinks resolve to the real script files in sibling<br/>
&nbsp; &nbsp; topic-grouped directories alongside `bin/`.

<br/>

## Quick Start
```
# Get the software:
$ git clone https://github.com/John-D-B/Claudes.git
$ dir="$PWD/Claudes/2026-06-01.EJBCA-tools"
$ export PATH="$dir/bin:$PATH"

# Install Python requirements:
$ cd "$dir"
$ pip install -r ./cg/requirements.txt
$ # (not needed for deploy_ejbca_k8s.py — stdlib only)
$ pip install -r ./elt/requirements.txt

# Confirm the scripts run by showing their versions:
$ cert-grep.py --version
$ deploy_ejbca_k8s.py --version
$ ejbca-lifecycle-tool.py --version
```

The symlink layout keeps `bin/` as a single flat namespace for your shell,<br/>
&nbsp; &nbsp; while the real sources live in topic directories that can hold per-tool<br/>
&nbsp; &nbsp; tests, fixtures, README files, or anything else without cluttering the<br/>
&nbsp; &nbsp; user-facing PATH entry.

<br/>

## What's here

| Symlink | Resolves to | What it does |
|---|---|---|
| `deploy_ejbca_k8s.py` | `../dek/deploy_ejbca_k8s.py` | Deploys cert-manager + the EJBCA cert-manager-issuer into a Kubernetes cluster,<br/>then issues a test certificate end-to-end against an EJBCA backend. |
| `ejbca-lifecycle-tool.py` | `../elt/ejbca-lifecycle-tool.py` | **ELT.** Direct EJBCA REST/SOAP client for listing, enrolling, revoking,<br/>&nbsp; &nbsp; and reaping End Entities and certificates. |
| `cert-grep.py` | `../cg/cert-grep.py` | Standalone X.509 diagnostic.<br/>Reads PEM (or DER) on stdin or by path, emits a chosen `summary_N` view of the cert internals.<br/>Used as a better alternative to `openssl x509 -text -noout`. |

Each tool ships with its own `--help` and a top-level docstring that describes<br/>
&nbsp; &nbsp; its full feature set. Run `<tool>.py --help` for the authoritative list of<br/>
&nbsp; &nbsp; flags and subcommands.

Each tool's source directory (`cg/`, `dek/`, `elt/`) also contains a per-tool<br/>
&nbsp; &nbsp; `README-<tool>.md` with longer-form documentation than this file provides.

<br/>

## Per-tool dependencies and assets

Each tool's source directory holds its own `requirements.txt` (for Python<br/>
&nbsp; &nbsp; package dependencies) and any auxiliary files the tool needs at runtime —<br/>
&nbsp; &nbsp; for example, `elt/wsdl/ejbca-ws.wsdl` (the SOAP descriptor ELT loads when<br/>
&nbsp; &nbsp; talking to EJBCA's legacy interface) and `cg/images/` (reference fixtures<br/>
&nbsp; &nbsp; for `cert-grep`).

The opening quick-start block above shows how to install these via<br/>
&nbsp; &nbsp; `pip install -r`. Use a virtualenv if you prefer isolation from your<br/>
&nbsp; &nbsp; system Python.

**Symlink invocation finds the sibling files correctly.** The published<br/>
&nbsp; &nbsp; scripts use `Path(__file__).resolve()` (or equivalent) to locate their<br/>
&nbsp; &nbsp; own directory, so when you run `ejbca-lifecycle-tool.py` through the<br/>
&nbsp; &nbsp; `bin/` symlink, Python's `__file__` resolves to the real path inside<br/>
&nbsp; &nbsp; `elt/` and the WSDL lookup at `elt/wsdl/ejbca-ws.wsdl` succeeds. You<br/>
&nbsp; &nbsp; don't need to invoke the tools from their source directories; PATH<br/>
&nbsp; &nbsp; invocation works fully.

<br/>

## Platform notes

**Mac and Linux:** works as-is after `git clone`. Symlinks and executable bits<br/>
&nbsp; &nbsp; are preserved by Git on Unix. Just add this directory to your `$PATH`.

**Windows:** Git for Windows materialises symlinks as plain text files unless<br/>
&nbsp; &nbsp; `core.symlinks=true` is set AND the user has the developer-mode symlink<br/>
&nbsp; &nbsp; permission. If you're on Windows and the `bin/` scripts read as one-line<br/>
&nbsp; &nbsp; text files saying `../dek/deploy_ejbca_k8s.py` etc., either fix the Git<br/>
&nbsp; &nbsp; config and re-clone, or skip `bin/` entirely and invoke the tools from<br/>
&nbsp; &nbsp; their resolved paths, eg:
- `$dir/dek/deploy_ejbca_k8s.py`
- `$dir/elt/ejbca-lifecycle-tool.py`
- `$dir/cg/cert-grep.py`

<br/>

## Why not put the scripts directly in `bin/`?

The split lets each tool own its own directory for sibling material that<br/>
&nbsp; &nbsp; doesn't belong on the user-facing PATH — per-tool READMEs, test fixtures,<br/>
&nbsp; &nbsp; reference YAML, license files, etc. `bin/` stays a tidy namespace; the<br/>
&nbsp; &nbsp; topic dirs handle everything else.
