# `deploy_ejbca_k8s.py`

**Author:**  JohnB, with AI pair-programming support by Anthropic Claude<br/>
**Date:** 2026-06-01


This is a single-file Python tool that deploys **cert-manager** and the<br/>
&nbsp; &nbsp; **EJBCA cert-manager external issuer** into a Kubernetes cluster, then issues<br/>
&nbsp; &nbsp; a test certificate end-to-end against an **EJBCA** backend.

The script is an idempotent re-implementation of the Keyfactor tutorial<br/>
&nbsp; &nbsp; *"Use EJBCA with cert-manager"* (vendor version 9.3.2). Each tutorial<br/>
&nbsp; &nbsp; sub-step is one Python function with a matching `# tutorial step N.M`<br/>
&nbsp; &nbsp; comment, so any line in the script can be traced back to the vendor doc.

This script is also useful to create test conditions for bug fixes to cert-manager's **EJBCA-Issuer**,<br/>
&nbsp; &nbsp; and the **DBMS Reaper** & **REST-API Certificate Delete** pull-requests for EJBCA-CE & EJBCA-EE.

Vendor URL:<br/>
<https://docs.keyfactor.com/ejbca/9.3.2/tutorial-use-ejbca-with-cert-manager>

This deploy script can share configuration variables with my partner script **ELT**:<br/>
&nbsp; &nbsp; `ejbca-lifecycle-tool.py`

This deploy script works best when **cert-grep.py** is available in the `$PATH`.<br/>

To see this tool in a full end-to-end story (EJBCA-CE stack + PR verification +<br/>
&nbsp; &nbsp; renewal-accumulation cleanup), see [`../ejbca-ce/DEMO.md`](../ejbca-ce/DEMO.md).<br/>

<br/>

## What you get

`deploy_ejbca_k8s.py` is a  working pipeline that, on a single command:

1. Verifies your EJBCA RA credential is present and usable.
2. Installs (or detects an existing) **cert-manager** in the cluster.
3. Installs (or detects an existing) **ejbca-cert-manager-issuer**.
4. Creates an `Issuer` (and `ClusterIssuer`) bound to your EJBCA backend.
5. Creates a `Certificate` object and waits for cert-manager to enroll it.
6. Extracts the issued certificate from the resulting `Secret` and pretty-prints it.

The pipeline is split into 28 named steps. Each step writes its own log,<br/>
&nbsp; &nbsp; rendered YAML, and JSON status to a timestamped output directory, so a<br/>
&nbsp; &nbsp; failed run can be inspected step-by-step without re-running anything.

<br/>

## Requirements

- Python 3.8 or later.
- `kubectl` and `helm` on `$PATH`, with a working `kubectl current-context`.
- An EJBCA instance reachable from the cluster (community or enterprise edition).
- An RA credential (PEM cert + key) authorised against EJBCA's REST API.
- A CA-bundle PEM that validates the EJBCA server certificate.
- Optionally, `cert-grep` on `$PATH` — used by step `5.100` to pretty-print<br/>
  &nbsp; &nbsp; the issued certificate. Falls back to `openssl x509 -text -noout` when<br/>
  &nbsp; &nbsp; `cert-grep` is absent.

No new Python dependencies are introduced. The script shells out to the<br/>
&nbsp; &nbsp; standard tools above rather than reinventing a Kubernetes or EJBCA client.

<br/>

### RA-credential resolution

Access to EJBCA via the REST-API requires an **RA Credential** certificates and key.<br/>
The script provides three ways to supply the RA credential, in precedence order:

1. `--ra-cred CERT_PATH,KEY_PATH` flag.
2. `--elt` (asserts `ELT_CERT` and `ELT_KEY` are set; reads them).
3. Module-load fallback to the env-var values, or to the bundled defaults<br/>
   &nbsp; &nbsp; if no env vars are set.

A `ra_cred_source` field in `config.json` records which path resolved the<br/>
&nbsp; &nbsp; current run's config.

<br/>

### Bootstrapping the RA credential

This deploy script does not create the RA credential — it expects an existing<br/>
&nbsp; &nbsp; one. The standard EJBCA path is: create an End Entity on the ManagementCA<br/>
&nbsp; &nbsp; (CN of your choosing, e.g. `ELT-Admin`), enrol it with REST-API role<br/>
&nbsp; &nbsp; membership, then export the resulting certificate + key as PEM. The<br/>
&nbsp; &nbsp; vendor's admin-management UI and CLI both support this; any standard<br/>
&nbsp; &nbsp; EJBCA bootstrap walkthrough applies.

For convenience, here's the GitHub publication of this tool:<br/>
&nbsp; &nbsp; <https://github.com/John-D-B/Claudes/tree/main/2026-06-01.EJBCA-tools>

The same source project also ships<br/>
&nbsp; &nbsp; a shell helper (`ejbca-ce/Bin/210.bootstrap/214.create-admin.sh`) that automates the<br/>
&nbsp; &nbsp; End-Entity-and-PEM-export workflow against a local EJBCA Community Edition<br/>
&nbsp; &nbsp; container — useful as a reference implementation if you'd rather not<br/>
&nbsp; &nbsp; click through the admin UI.

The resulting files are typically named `<env>-eltadmin.crt` / `.key` (e.g.<br/>
&nbsp; &nbsp; `ce-eltadmin.crt` for a Community Edition target, `ee-eltadmin.crt` for<br/>
&nbsp; &nbsp; an Enterprise Edition target) — the naming is purely convention, but<br/>
&nbsp; &nbsp; the deploy script's `local-fixes` preset assumes the CE pair lives at<br/>
&nbsp; &nbsp; `Creds/elt/ce-eltadmin.{crt,key}` relative to the project root.

<br/>

## Quick start

FYI:

```text
$ deploy_ejbca_k8s.py --version
$ deploy_ejbca_k8s.py --help

$ deploy_ejbca_k8s.py show      --help
$ deploy_ejbca_k8s.py set       --help
$ deploy_ejbca_k8s.py do        --help
$ deploy_ejbca_k8s.py run       --help
$ deploy_ejbca_k8s.py probe-ca  --help

```

Configure once, then run:

```text
$ deploy_ejbca_k8s.py set --preset local-fixes
$ deploy_ejbca_k8s.py show
$ deploy_ejbca_k8s.py do
```

`set` persists configuration to a JSON file in a fresh timestamped output<br/>
&nbsp; &nbsp; directory. `do` reads that file, executes every step in order, and prints<br/>
&nbsp; &nbsp; a per-step status table plus a cleanup-commands block at the end.

To stop after the issuer is deployed (skipping the test-certificate issuance):

```text
$ deploy_ejbca_k8s.py do --to 4.14
```

To re-show the most recently issued certificate without re-running the pipeline:

```text
$ deploy_ejbca_k8s.py run 5.100
```

<br/>

## Subcommands

`set` — Write a `config.json` into a fresh timestamped output directory.<br/>
&nbsp; &nbsp; Accepts every configuration flag the pipeline understands. Subsequent<br/>
&nbsp; &nbsp; `do` / `show` / `run` invocations read from this file.

`show` — Print the resolved configuration from the most-recent run directory.<br/>
&nbsp; &nbsp; Add `--full` for the complete JSON dump.

`do` — Execute every step in order, in a freshly-timestamped output directory.<br/>
&nbsp; &nbsp; Console output is one line per step (status + elapsed time); failures<br/>
&nbsp; &nbsp; replay their full stderr inline with a hint pointing at the captured log<br/>
&nbsp; &nbsp; file. `--from STEP` and `--to STEP` scope the run; `--dry-run` writes<br/>
&nbsp; &nbsp; rendered YAML to disk without touching the cluster.

`run STEP [STEP ...]` — Execute one or more specific steps ad-hoc, in the<br/>
&nbsp; &nbsp; most-recent output directory. Typically used for iterative inspection<br/>
&nbsp; &nbsp; (`run 5.100` to re-render the cert summary, `run 4.14` to re-check Issuer<br/>
&nbsp; &nbsp; readiness, etc.).

`probe-ca` — Standalone pre-flight check that hits EJBCA's `/v1/ca` REST<br/>
&nbsp; &nbsp; endpoint and asserts the configured `certificateAuthorityName` actually<br/>
&nbsp; &nbsp; exists. Useful for catching CA-rename drift before a full `do` run.

## Step reference

The script implements the vendor tutorial's Step 1 through Step 5 sub-chapter<br/>
&nbsp; &nbsp; *"Certificate Kind Object Request"* — 28 steps in total. Function names<br/>
&nbsp; &nbsp; use `x` as a dot-substitute (e.g. `step_4x7_*` for tutorial step 4.7),<br/>
&nbsp; &nbsp; since Python identifiers can't contain dots. The dispatch table keys are<br/>
&nbsp; &nbsp; the literal dotted IDs (`"4.7"`), and the comment headers above each<br/>
&nbsp; &nbsp; function spell out the tutorial reference. Three greps for the same step,<br/>
&nbsp; &nbsp; all unambiguous.

| ID | Phase | What it does |
|---|---|---|
| `1` | RA role | Verifies the configured RA credential resolves and is readable. |
| `2` | RA credential | Parses the RA cert to confirm it's well-formed (cert-grep or openssl). |
| `3.1`–`3.4` | cert-manager | Adds the Jetstack Helm repo, installs the CRDs, deploys cert-manager. |
| `4.2`–`4.8` | EJBCA issuer | Creates namespaces, the RA-credential Secret, the CA-bundle Secret, and installs the ejbca-cert-manager-issuer Helm chart. |
| `4.9`–`4.14` | Issuer object | Renders and applies `Issuer` and `ClusterIssuer` YAML, plus the approver-RBAC ClusterRole; waits for `Ready: True`. |
| `5.1`–`5.8` | Issue a cert | Renders and applies a `Certificate`, watches the resulting `CertificateRequest`, and confirms the populated `Secret`. |
| `5.100` | Show the cert | Extracts the issued cert from the Secret and renders the full X.509 details.<br/>Not in the vendor tutorial; added because every cert-issuance walkthrough stops one step short of actually showing the cert. |

Steps 3.4, 4.6, and 4.7 auto-detect already-installed components (cert-manager,<br/>
&nbsp; &nbsp; the issuer Helm release) and skip the install rather than fight over<br/>
&nbsp; &nbsp; Helm ownership. This lets the script coexist with other tooling that<br/>
&nbsp; &nbsp; provisioned the same components.

<br/>

## Configuration

Configuration is layered, with later sources overriding earlier:

1. **Built-in defaults** — sensible values for a local deployment.
2. **Saved config** — `config.json` in the most-recent output directory.
3. **Environment variables** — see below.
4. **Preset** — `--preset local-fixes` applies a bundled named profile.
5. **`--elt`** — explicitly read the `ELT_*` env vars and assert they're set.
6. **CLI flags** — every saved field has a `--flag` override.

The full configuration is persisted as JSON. `show` prints the derived subset<br/>
&nbsp; &nbsp; that drives the manifests (CA name, profile names, RA cert/key paths, host,<br/>
&nbsp; &nbsp; etc.); `show --full` dumps every field including the cluster context,<br/>
&nbsp; &nbsp; SAN lists, and grouping mode.

<br/>

### Environment variables

The following are honoured at every invocation (non-empty value wins over<br/>
&nbsp; &nbsp; saved config; unset env doesn't clobber the saved value):

| Variable | Maps to |
|---|---|
| `ELT_CERT` | RA-credential cert path |
| `ELT_KEY` | RA-credential key path |
| `ELT_CA_BUNDLE` (or `ELT_CA_CERT` as fallback) | CA bundle PEM path |
| `ELT_HOST` (+ optional `ELT_PORT`) | EJBCA host (and port) |
| `ELT_CA_NAME` | EJBCA `certificateAuthorityName` |
| `ELT_CERT_PROFILE` | EJBCA `certificateProfileName` |
| `ELT_EE_PROFILE` | EJBCA `endEntityProfileName` |
| `ELT_KEY_ALGORITHM` | Certificate private-key algorithm |
| `ELT_KEY_SIZE` | Certificate private-key size |
| `ELT_COUNTRY` | Subject DN `C=` |
| `ELT_ORGANIZATIONAL_UNIT` | Subject DN `OU=` |
| `BD_CERT_NAME` | Certificate object's name, or `RANDOM` |
| `BD_SECRET_NAME` | Secret name, or `RANDOM` |

<br/>

### Duration

`--duration` (or `-d`) must be a Go-style duration string —<br/>
&nbsp; &nbsp; `1h`, `30m`, `2160h`, `1h30m`. Days, weeks, months, and years are not<br/>
&nbsp; &nbsp; supported (a constraint inherited from cert-manager's webhook); convert<br/>
&nbsp; &nbsp; to hours. Invalid values are rejected at `set` / `do` time with a list<br/>
&nbsp; &nbsp; of working examples, rather than waiting for the cert-manager admission<br/>
&nbsp; &nbsp; webhook to reject the apply at step 5.2.

<br/>

## Output artefacts

By default, every `do` invocation creates a fresh timestamped directory under<br/>
&nbsp; &nbsp; `/tmp/claude/k8s/`. Override with `--output-dir PATH`.

Inside the directory:

`config.json` — the configuration the run executed against.

`summary.txt` — human-readable per-step status table.

`all.log` — concatenated stdout/stderr of every shell-out the run made.<br/>
&nbsp; &nbsp; Each block is preceded by the literal `$ kubectl ...` command line<br/>
&nbsp; &nbsp; that produced it, so the log is self-contextualizing.

`all.yaml` — concatenated rendered YAML manifests (Issuer, ClusterIssuer,<br/>
&nbsp; &nbsp; RBAC, Secret, Certificate). Useful as paste-ready reference material.

`all.json` — concatenated per-step JSON status records<br/>
&nbsp; &nbsp; (exit codes, artefact paths, hints).

`step_5x100.pem` — the issued certificate, extracted from its Secret.

Alternative groupings via `--grouping`:

- `all` (default) — one `all.*` file per kind, as above.
- `sections` — one file per phase: `section_pre.log`, `section_1.log`, etc.
- `steps` — one file per step: `step_4x9_*.log`, `step_5x100_*.yaml`, etc.

The on-disk artefacts always carry the *full* untruncated output, regardless<br/>
&nbsp; &nbsp; of any console-side truncation.

<br/>

## Fresh-issuance modes (orphan generation)

For testing scenarios that benefit from many distinct certs being issued —<br/>
&nbsp; &nbsp; for example, exercising EJBCA-side reaper code that cleans up revoked<br/>
&nbsp; &nbsp; certificate records — the script honours two environment variables<br/>
&nbsp; &nbsp; (with matching CLI flags) that, when set to the literal value `RANDOM`,<br/>
&nbsp; &nbsp; append a 4-digit suffix to the K8s object names on every `do` run:

`BD_SECRET_NAME=RANDOM` (or `--secret-name RANDOM`) — appends a 4-digit suffix<br/>
&nbsp; &nbsp; to the Secret name only. cert-manager sees `spec.secretName` change,<br/>
&nbsp; &nbsp; re-issues, and the previous Secret is left as an unmanaged orphan. The<br/>
&nbsp; &nbsp; Certificate object's name is unchanged, so EJBCA-side enrollments all<br/>
&nbsp; &nbsp; land on the same End Entity and accumulate auto-revoked predecessor<br/>
&nbsp; &nbsp; records.

`BD_CERT_NAME=RANDOM` (or `--cert-name RANDOM`) — appends the same kind of<br/>
&nbsp; &nbsp; suffix to the Certificate object's name. Each run produces a brand-new<br/>
&nbsp; &nbsp; Certificate object, which unambiguously triggers a fresh<br/>
&nbsp; &nbsp; `CertificateRequest` and ejbca-issuer enrollment.

When both variables are set to `RANDOM`, the same 4-digit suffix is shared so<br/>
&nbsp; &nbsp; the Certificate and Secret names match — `Certificate/<base>-NNNN` ↔<br/>
&nbsp; &nbsp; `Secret/<base>-NNNN` — easy to correlate across<br/>
&nbsp; &nbsp; `$ kubectl get certificate -A` and `$ kubectl get secret -A`.

The `RANDOM` value survives across runs: it persists in `config.json` after<br/>
&nbsp; &nbsp; resolution, so a single `set --secret-name RANDOM` (or `$ export BD_SECRET_NAME=RANDOM`<br/>
&nbsp; &nbsp; in the shell) followed by repeated `do`<br/>
&nbsp; &nbsp; invocations produces a fresh suffix on each run.

The Issuer YAML sets `endEntityName: cn` explicitly. This locks ejbca-issuer<br/>
&nbsp; &nbsp; to derive the EJBCA End Entity username from the CSR's CommonName, so all<br/>
&nbsp; &nbsp; enrollments under fresh-issuance mode land on the same EE regardless of<br/>
&nbsp; &nbsp; the K8s-side naming churn.

<br/>

## Cleanup

After every `do` run, the script prints a `=== Cleanup ===` block with the<br/>
&nbsp; &nbsp; exact `kubectl` commands needed to remove the run's K8s artefacts. The<br/>
&nbsp; &nbsp; same block is appended to `all.log` and `summary.txt` for later reference.

Two options per scope:

**Option A — Stop renewals, keep the issued cert material.**<br/>
&nbsp; &nbsp; Uses `$ kubectl delete certificate <name> --cascade=orphan`, leaving the<br/>
&nbsp; &nbsp; Secret in place. cert-manager loses the Certificate it was reconciling,<br/>
&nbsp; &nbsp; so no further renewals fire. The cert in the Secret remains valid until<br/>
&nbsp; &nbsp; its `notAfter`; anything mounting that Secret keeps working.

**Option B — Remove everything.**<br/>
&nbsp; &nbsp; Default cascade. Deletes the Certificate and its currently-owned Secret.<br/>
&nbsp; &nbsp; Use when the cert is no longer needed anywhere.

When `BD_CERT_NAME=RANDOM` or `BD_SECRET_NAME=RANDOM` was in effect during<br/>
&nbsp; &nbsp; the run, a second pair of Option A / Option B commands appears, scoped<br/>
&nbsp; &nbsp; to *all prior RANDOM-mode runs* — one-shot recipes for sweeping<br/>
&nbsp; &nbsp; accumulated orphan Certificates and Secrets across the namespace.

Neither option touches EJBCA-side state. The End Entity and any revoked<br/>
&nbsp; &nbsp; cert records persist across K8s-side cleanup — that's intentional, and<br/>
&nbsp; &nbsp; is the domain of the EJBCA reaper rather than this script.

<br/>

## Verbosity

| Mode | Per-step header | Per-step OK | Per-step FAIL |
|---|---|---|---|
| default | shown | one-liner | full stderr + hint inline |
| `--verbose` | shown | full stdout inline | full stdout + stderr + hint inline |
| `--errors-only` | suppressed | suppressed | full stderr + hint inline |
| `--dry-run` | shown | YAML / command printed, not executed | n/a |

Subprocess output is truncated at 125 columns in the console only; the<br/>
&nbsp; &nbsp; on-disk log keeps the full text. Long status messages are wrapped to<br/>
&nbsp; &nbsp; 80 columns with hanging indentation.

<br/>

## Console layout

Every `do` invocation prints, in order:

- Script version banner.
- Run-output directory header.
- One section per pipeline phase, each containing per-step blocks.
- `=== Summary ===` line with the OK/WARN/FAIL/SKIP counts.
- `=== Cleanup ===` block with paste-ready `kubectl delete` commands.

Each per-step block reads top-down:

```text
  [4.9] step_4x9_create_issuer_yaml_file
    rendered Issuer YAML:

      apiVersion: ejbca-issuer.keyfactor.com/v1alpha1
      kind: Issuer
      ...
                                                       OK (3ms)
```

The step header precedes its body output, and the status line closes the<br/>
&nbsp; &nbsp; block. Steps `4.9`, `4.11`, and `5.1` inline-render the full Issuer,<br/>
&nbsp; &nbsp; ClusterIssuer, and Certificate manifests — copy-paste-ready reference<br/>
&nbsp; &nbsp; material for anyone adapting the script's output into their own<br/>
&nbsp; &nbsp; deployment.
