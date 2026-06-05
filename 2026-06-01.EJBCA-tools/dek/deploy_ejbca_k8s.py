#!/usr/bin/env python3
"""deploy_ejbca_k8s.py — encapsulate the Keyfactor 9.3.2 "Use EJBCA with cert-manager"
tutorial as one idempotent Python tool.

Vendor URL:   https://docs.keyfactor.com/ejbca/9.3.2/tutorial-use-ejbca-with-cert-manager
Local copy:   ../Docs2/tutorial-use-ejbca-with-cert-manager-9.3.2.md
Design doc:   ../Docs2/deploy-ejbca-k8s.PROPOSAL.md  (v3)

Runtime: standard Python 3 (no venv needed). The ELT-runtime rule in
CLAUDE.md applies only to ejbca-lifecycle-tool.py (which needs `zeep` for
SOAP) — this script uses only the Python stdlib and shells out to
kubectl / helm / openssl / curl / cert-grep.

Quick usage (invoke however you prefer):
    ./Binp/deploy_ejbca_k8s.py set --preset local-fixes --duration 1h
    ./Binp/deploy_ejbca_k8s.py show
    ./Binp/deploy_ejbca_k8s.py do
    ./Binp/deploy_ejbca_k8s.py run 5.100   # re-show the cert without re-issuing
    ./Binp/deploy_ejbca_k8s.py probe-ca    # standalone CA-rename guard

Per-step function naming:
    step_NxM_descriptive()    where x = literal `.` (Python identifiers can't contain dots).
                              e.g. step_4x7_*  is tutorial 4.7.
    pre_descriptive()         pre-flight helpers; no tutorial step number.
    grep step_4x7             lands on the function definition.
    grep '"4.7"'              lands on the STEPS dispatch entry.
    grep 'tutorial step 4.7'  lands on the function's comment header.

Author: ThreeSter (Anthropic Claude Code), for JohnB.
"""

from __future__ import annotations

__version__ = "2.24.0"

import argparse
import dataclasses
import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional


# ===========================================================================
#  Constants and defaults
# ===========================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent      # parent of Binp/
DEFAULT_OUTPUT_PARENT = Path("/tmp/claude/k8s")            # per CLAUDE.md hard convention


def _env_or(env_var: str, fallback: str) -> str:
    """Return os.environ[env_var] if set and non-empty, else fallback.

    Used at module-load time to honour `ELT_*` environment variables as
    implicit defaults — so the script picks up the user's existing
    `elt-env` exports automatically, without requiring `--elt` or
    `--ra-cred`. Particularly important when the script is symlinked
    or relocated to a path where `PROJECT_ROOT/Creds/elt/...` doesn't
    point at the user's real credential files.
    """
    val = os.environ.get(env_var)
    return val if val else fallback


def _env_int(env_var: str, fallback: int) -> int:
    """Like `_env_or` but coerces to int; falls back on empty or non-numeric."""
    val = os.environ.get(env_var)
    if not val:
        return fallback
    try:
        return int(val)
    except ValueError:
        return fallback


# Go-style duration regex (cert-manager's Certificate.spec.duration accepts
# whatever Go's time.ParseDuration accepts: one or more `<number><unit>`
# segments, units restricted to ns / us / µs / ms / s / m / h. No days,
# weeks, months, or years — the cert-manager webhook rejects those at
# apply time with "unknown unit". Validating up-front gives the user a
# fast error with copy-paste examples rather than a 5-step pipeline that
# only fails at step 5.2.
_GO_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+$")


def _validate_duration(d: str) -> None:
    """Raise SystemExit with examples if `d` isn't a valid Go duration.
    Empty string is treated as "no duration set" and accepted (uses
    cert-manager's default of 90 days when omitted from the manifest)."""
    if not d:
        return
    if _GO_DURATION_RE.match(d):
        return
    raise SystemExit(
        f"invalid duration {d!r} — cert-manager's Certificate.spec.duration\n"
        "uses Go's time.Duration syntax (units: ns, us, µs, ms, s, m, h).\n"
        "Days / weeks / months / years are NOT supported — convert to hours.\n"
        "\n"
        "Examples that work:\n"
        "    1h           1 hour\n"
        "    30m          30 minutes\n"
        "    24h          1 day\n"
        "    168h         1 week\n"
        "    2160h        90 days  (cert-manager's default if omitted)\n"
        "    8760h        1 year   (365 days)\n"
        "    1h30m        1 hour 30 minutes (combined units)\n"
    )


# Credentials — `ELT_*` env vars take precedence over the script-relative
# fall-back paths. `--ra-cred` / `--elt` still override at parse time.
DEFAULT_RA_CERT = _env_or("ELT_CERT",
                          str(PROJECT_ROOT / "Creds/elt/ce-eltadmin.crt"))
DEFAULT_RA_KEY = _env_or("ELT_KEY",
                         str(PROJECT_ROOT / "Creds/elt/ce-eltadmin.key"))
# ELT_CA_BUNDLE is the canonical name (matches the deploy script's --ca-bundle
# flag and Bin/3.8 harness). ELT_CA_CERT is honoured as a fallback because
# Bin/elt/ce-target.env and pre-existing ELT-tool conventions use that name —
# in practice the two refer to the same file, so reusing one variable for
# both consumers is the friendlier default.
DEFAULT_CA_BUNDLE = _env_or("ELT_CA_BUNDLE",
                            _env_or("ELT_CA_CERT",
                                    str(PROJECT_ROOT / "Creds/elt/ce-managementca.crt")))

# EJBCA backend addressed via host.k3d.internal per CLAUDE.md, unless
# overridden by ELT_HOST (+ optional ELT_PORT).
def _default_ejbca_host() -> str:
    h = os.environ.get("ELT_HOST")
    p = os.environ.get("ELT_PORT")
    if h and p:
        return f"{h}:{p}"
    if h:
        return h    # user is responsible for including the port if needed
    return "host.k3d.internal:8443"

DEFAULT_EJBCA_HOST = _default_ejbca_host()

# Namespaces & names per vendor 9.3.2 tutorial.
DEFAULT_ISSUER_NAMESPACE = "ejbca-cert-manager"
DEFAULT_PKI_NAMESPACE = "pkirules"
DEFAULT_ISSUER_NAME = "pkirules-tls"
DEFAULT_CLUSTERISSUER_NAME = "clusterissuer-pkirules"

# Chart pin — see PROPOSAL.md §"Step 4.7 rationale".
DEFAULT_CHART_TAG = "2.2.1"

# Cert-manager release pinning — defaults to GitHub-Releases-API latest stable
# at runtime; --cert-manager-version overrides.
DEFAULT_CERT_MANAGER_VERSION = "latest"   # resolved at runtime

# EJBCA profile / CA names — overridable via ELT_* env vars at module-load
# time. These match the local CE stack's ELT-* profiles; users with other
# profile names should export ELT_CA_NAME / ELT_CERT_PROFILE / ELT_EE_PROFILE
# (or pass the corresponding --ca-name / --cert-profile / --ee-profile flag).
DEFAULT_CA_NAME = _env_or("ELT_CA_NAME", "ManagementCA")
DEFAULT_CERT_PROFILE = _env_or("ELT_CERT_PROFILE", "ELT-Server-profile")
DEFAULT_EE_PROFILE = _env_or("ELT_EE_PROFILE", "ELT-Server-End-Entity")

# Private-key algorithm/size for the cert-manager Certificate object.
# Defaults RSA-4096 match the project's reference template; override via
# ELT_KEY_ALGORITHM / ELT_KEY_SIZE or --key-algorithm / --key-size.
DEFAULT_KEY_ALGORITHM = _env_or("ELT_KEY_ALGORITHM", "RSA")
DEFAULT_KEY_SIZE = _env_int("ELT_KEY_SIZE", 4096)

# Cert defaults — by default the Subject is CN-only (matches both JohnB's
# TMP_f_cert_manager_5.txt template AND JohnB's ELT-Server-End-Entity
# profile, which doesn't accept O/C fields). Tutorial-faithful users can
# pass --country / --organization / --organizational-unit explicitly if
# their EE profile expects those.
DEFAULT_DURATION = "1h"
DEFAULT_COUNTRY = _env_or("ELT_COUNTRY", "")
DEFAULT_ORG = ""
DEFAULT_OU = _env_or("ELT_ORGANIZATIONAL_UNIT", "")

# Secret-name override (v2.6.0). Empty = the Secret name matches the
# Certificate name (cert-manager's default and the script's pre-v2.5.0
# behaviour). 'RANDOM' (case-insensitive) generates a 4-digit suffix per
# `do` invocation and applies it to the Secret name only (cert_name is
# left untouched). This forces cert-manager to re-issue (different
# spec.secretName each run), and because the Certificate object's name
# stays constant, ejbca-issuer enrols against the SAME End Entity on
# EJBCA every run — triggering EJBCA's auto-revoke-prior-cert behaviour
# and accumulating revoked-cert records on that EE for reaper testing.
# Any other literal value is used as the Secret name verbatim.
DEFAULT_SECRET_NAME = _env_or("BD_SECRET_NAME", "")

# Repo URLs.
JETSTACK_REPO_NAME = "jetstack"
JETSTACK_REPO_URL = "https://charts.jetstack.io"
EJBCA_ISSUER_REPO_NAME = "ejbca-issuer"
EJBCA_ISSUER_REPO_URL = "https://keyfactor.github.io/ejbca-cert-manager-issuer"
EJBCA_ISSUER_CHART = "ejbca-issuer/ejbca-cert-manager-issuer"
CERT_MANAGER_CRDS_URL_TPL = "https://github.com/cert-manager/cert-manager/releases/download/{ver}/cert-manager.crds.yaml"
CERT_MANAGER_GH_LATEST = "https://api.github.com/repos/cert-manager/cert-manager/releases/latest"

# Presets — preset-driven configurations for known targets.
PRESETS = {
    "local-fixes": {
        # Local EJBCA-CE stack from this project (Phase 1 / Phase 2).
        # Profile/CA names defer to ELT_* env vars (via DEFAULT_*) so a
        # user with custom profile names still gets honoured under --preset.
        "ejbca_host": DEFAULT_EJBCA_HOST,
        "ca_name": DEFAULT_CA_NAME,
        "cert_profile": DEFAULT_CERT_PROFILE,
        "ee_profile": DEFAULT_EE_PROFILE,
        "ra_cert": str(DEFAULT_RA_CERT),
        "ra_key": str(DEFAULT_RA_KEY),
        "ca_bundle": str(DEFAULT_CA_BUNDLE),
        "pki_namespace": DEFAULT_PKI_NAMESPACE,
    },
}


# ===========================================================================
#  Helpers
# ===========================================================================

# Console output truncation (per JohnB v2.3.0 request): subprocess output
# lines, after indentation, are cut to this many characters when emitted
# to the terminal. The on-disk all.log (populated separately from
# _stdout_chunks) keeps the full untruncated text. Equivalent to
# `... | cut -c1-CONSOLE_LINE_TRUNC`.
CONSOLE_LINE_TRUNC = 125


class _DedupedStdout:
    """sys.stdout wrapper that tracks whether the most recently completed
    line was blank, and exposes `blank_line()` which suppresses an emitted
    newline if the last line was already blank.

    Implemented as a wrapper so every `print()` automatically updates the
    state — no need to route step-body status `print()` calls through a
    bespoke helper. The wrapper installs itself at module load and stays
    for the lifetime of the process.
    """
    def __init__(self, underlying):
        self.underlying = underlying
        self._pending = ""             # bytes since last newline
        self._last_complete_blank = True  # treat start-of-stream as blank

    def write(self, s):
        if not s:
            return
        self.underlying.write(s)
        combined = self._pending + s
        lines = combined.split("\n")
        for line in lines[:-1]:
            self._last_complete_blank = (line.strip() == "")
        self._pending = lines[-1]

    def flush(self):
        self.underlying.flush()

    def isatty(self):
        return self.underlying.isatty() if hasattr(self.underlying, "isatty") else False

    def blank_line(self):
        """Emit a blank line, unless the last complete line was already blank."""
        if self._pending:
            # Mid-line: end the current line first (rare in practice).
            self.underlying.write("\n")
            self._last_complete_blank = (self._pending.strip() == "")
            self._pending = ""
        if not self._last_complete_blank:
            self.underlying.write("\n")
            self._last_complete_blank = True


# Install at module load so every print() — including the version banner
# emitted by main(), step-body status prints, and argparse output —
# updates the dedup state uniformly.
sys.stdout = _DedupedStdout(sys.stdout)


def _console_blank() -> None:
    """Convenience wrapper: ask the wrapped stdout to emit a dedup blank."""
    if isinstance(sys.stdout, _DedupedStdout):
        sys.stdout.blank_line()
    else:
        print()


def _console_yaml(yaml_text: str, label: str, indent_n: int = 4) -> str:
    """Print a rendered YAML manifest to console, indented as a body block
    under the current step header. Returns the printed block (label +
    indented YAML) so callers can also append it to ctx._stdout_chunks
    for the on-disk all.log.

    Layout (v2.15.0: blank line between label and body so the YAML
    visually separates from the description text — applies to console
    and to the on-disk artefact via the returned block):
        <indent_n spaces>{label}:
        <blank>
        <indent_n + 2 spaces><yaml line 1>
        <indent_n + 2 spaces><yaml line 2>
        ...

    Used by steps 4.9 / 4.11 / 5.1 (the "create <kind>.yaml file" steps)
    so the rendered Issuer / ClusterIssuer / Certificate manifests are
    visible inline as canonical reference examples — exactly what real
    users incorporating cert-manager into their applications need to see.
    """
    pad_label = " " * indent_n
    pad_body = " " * (indent_n + 2)
    body = "\n".join(pad_body + ln for ln in yaml_text.splitlines())
    block = f"{pad_label}{label}:\n\n{body}"
    print(block)
    return block


def _wrap_block(text: str, width: int = 80,
                subsequent_indent: str = "      ") -> str:
    """Wrap each line of `text` independently to `width` chars, applying
    `subsequent_indent` to continuation lines so wrapped error messages
    stay visually grouped under their first line.

    Used by Logger.failure_block to keep long curl / openssl / kubectl
    error lines from running off the right edge of an 80-col terminal.
    Existing line breaks in the input are preserved — only lines longer
    than `width` get wrapped, and they wrap inside word boundaries
    (`break_long_words=False`) so URLs and paths stay intact.

    v2.24.0: when an input line has leading whitespace, that whitespace
    is preserved on the wrapped first line via `initial_indent`. Without
    this, textwrap.fill would strip the leading indent and emit the
    first line flush-left — which destroys any structural indentation
    the caller used to nest the line under a label.
    """
    out_lines = []
    for line in text.splitlines():
        if not line.strip():
            out_lines.append("")
            continue
        if len(line) <= width:
            out_lines.append(line)
            continue
        # Preserve the input line's leading whitespace as initial_indent
        # so a wrapped indented line (e.g. `      <long path>`) keeps
        # its first-line indent rather than collapsing to flush-left.
        stripped = line.lstrip()
        leading = line[: len(line) - len(stripped)]
        wrapped = textwrap.fill(
            stripped, width=width,
            initial_indent=leading,
            subsequent_indent=subsequent_indent,
            break_long_words=False, break_on_hyphens=False,
        )
        out_lines.append(wrapped)
    return "\n".join(out_lines)


def _console_msg(msg: str, indent_n: int = 4,
                 max_width: int = 80) -> None:
    """Print a long status message to console, wrapped at `max_width`
    (default 80 chars per v2.11.0 — was 125 in v2.4.0–2.10.0, which JohnB
    found uncomfortably wide), with continuation lines re-indented to
    `indent_n` spaces so the block reads as one paragraph nested under
    the preceding step header.

    Step bodies that emit free-form status text (e.g., the
    cert-manager-already-deployed / ejbca-issuer-already-deployed /
    secret-namespace messages in steps 3.3 / 4.6 / 4.2) should call this
    rather than bare `print(msg)`, otherwise the lines run off the right
    edge of an 80-column terminal.

    The input `msg` may already include leading whitespace (e.g.
    `"    cert-manager already deployed ..."`) — we strip that first so
    textwrap's indent math is correct, then re-apply `indent_n`.
    """
    pad = " " * indent_n
    clean = textwrap.dedent(msg).strip()
    wrapped = textwrap.fill(clean, width=max_width,
                            initial_indent=pad, subsequent_indent=pad,
                            break_long_words=False, break_on_hyphens=False)
    print(wrapped)


def now_str() -> str:
    """YYYY-MM-DD_HH-MM-SS — JohnB's preferred timestamp form (no RFC3339 'T')."""
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def cmd_to_str(cmd) -> str:
    if isinstance(cmd, str):
        return cmd
    return " ".join(shlex.quote(c) for c in cmd)


def indent(text: str, n: int = 4) -> str:
    pad = " " * n
    return "\n".join(pad + ln for ln in text.splitlines())


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def run(cmd, env=None, input_data=None, cwd=None, timeout=180):
    """Run a command, return (returncode, stdout, stderr, elapsed_ms).

    `cmd` may be a list (preferred) or a string (executed via /bin/sh -c).
    """
    t0 = time.monotonic()
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    use_shell = isinstance(cmd, str)
    try:
        result = subprocess.run(
            cmd,
            shell=use_shell,
            capture_output=True,
            text=True,
            env=full_env,
            input=input_data,
            cwd=cwd,
            timeout=timeout,
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return result.returncode, result.stdout, result.stderr, elapsed_ms
    except subprocess.TimeoutExpired as e:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return 124, (e.stdout or "") if isinstance(e.stdout, str) else "", \
            ((e.stderr or "") if isinstance(e.stderr, str) else "") + \
            f"\n[TIMEOUT after {timeout}s]", elapsed_ms


def fmt_elapsed(ms: int) -> str:
    if ms < 1000:
        return f"{ms}ms"
    return f"{ms/1000:.1f}s"


def resolve_cert_manager_version(pinned: str) -> str:
    """Resolve cert-manager version via GitHub Releases API if 'latest'."""
    if pinned and pinned.lower() != "latest":
        return pinned
    rc, out, err, _ = run(["curl", "-fsSL", CERT_MANAGER_GH_LATEST], timeout=20)
    if rc == 0:
        try:
            data = json.loads(out)
            tag = data.get("tag_name")
            if tag:
                return tag
        except json.JSONDecodeError:
            pass
    # Fall back to a known-good if API unreachable.
    return "v1.13.3"


# ===========================================================================
#  Config — the persisted state (analogue of kca_* env vars)
# ===========================================================================

@dataclass
class Config:
    # EJBCA backend
    ejbca_host: str = DEFAULT_EJBCA_HOST
    ca_name: str = DEFAULT_CA_NAME
    cert_profile: str = DEFAULT_CERT_PROFILE
    ee_profile: str = DEFAULT_EE_PROFILE

    # RA credential (precedence: --ra-cred > --elt > preset > project default)
    ra_cert: str = str(DEFAULT_RA_CERT)
    ra_key: str = str(DEFAULT_RA_KEY)
    ca_bundle: str = str(DEFAULT_CA_BUNDLE)
    ra_cred_source: str = "default"   # "ra-cred" | "elt" | "preset" | "default"

    # Namespaces
    issuer_namespace: str = DEFAULT_ISSUER_NAMESPACE
    pki_namespace: str = DEFAULT_PKI_NAMESPACE

    # Issuer / ClusterIssuer names
    issuer_name: str = DEFAULT_ISSUER_NAME
    clusterissuer_name: str = DEFAULT_CLUSTERISSUER_NAME

    # Helm chart
    chart_tag: str = DEFAULT_CHART_TAG

    # cert-manager version (latest = resolve at runtime)
    cert_manager_version: str = DEFAULT_CERT_MANAGER_VERSION

    # Cert subject + SANs
    duration: str = DEFAULT_DURATION
    common_name: str = "k8s-cert-test.example.local"
    country: str = DEFAULT_COUNTRY
    organization: str = DEFAULT_ORG
    organizational_unit: str = DEFAULT_OU
    san_dns: list = field(default_factory=list)
    san_ip: list = field(default_factory=list)
    san_email: list = field(default_factory=list)
    cert_name: str = "k8s-cert-test"      # the Certificate object's name
    # Secret name (cert-manager spec.secretName). Empty → matches cert_name
    # (default). "RANDOM" → 4-digit suffix per `do` run, applied to BOTH
    # cert and secret to force re-issuance. Any other value → used as the
    # Secret name verbatim. Resolved by _resolve_secret_name() in cmd_do.
    secret_name: str = DEFAULT_SECRET_NAME

    # Private key algorithm + size for the Certificate object (cert-manager
    # privateKey spec). Default RSA-4096 matches the project's
    # TMP_f_cert_manager_5 reference template. Use --key-algorithm ECDSA
    # --key-size 256 for EE profiles that require EC keys. cert-manager-
    # supported algorithms: RSA (size 2048/4096/8192), ECDSA (size
    # 256/384/521), Ed25519 (size ignored).
    key_algorithm: str = DEFAULT_KEY_ALGORITHM
    key_size: int = DEFAULT_KEY_SIZE

    # Cluster context (optional, defaults to current kubectl context)
    kube_context: Optional[str] = None

    # HTTP proxy
    proxy: Optional[str] = None

    # Coexistence escape hatch — step 3.4 auto-skips if cert-manager is
    # already installed (Twoster's Bin/2.2 path); set True to force the
    # helm upgrade --install anyway (only useful if you know what you're doing).
    force_helm_cert_manager: bool = False

    # Same escape hatch for step 4.7 — auto-skips if the EJBCA issuer's
    # cluster-scoped CRD is already owned by another Helm release in another
    # namespace (Twoster's Bin/2.3 path → ejbca-issuer-system).
    force_helm_ejbca_issuer: bool = False

    # Output artefact grouping: "all" (default, one file for everything),
    # "sections" (one file per phase: pre, 1, 2, 3, 4, 5), or "steps"
    # (one file per step). Affects .log / .yaml / .json — use `jq` to
    # extract specific sections from the consolidated .json (each entry
    # tagged by step_id). Only .pem stays per-step (typically just one,
    # from step 5.100; cert PEMs aren't usefully concatenated).
    grouping: str = "all"

    # Cert-grep handling for step 5.100.
    # use_openssl=True: skip cert-grep entirely, use openssl; FAIL if
    #   openssl not on PATH (no silent no-op).
    # certgrep_path: explicit path to cert-grep binary (overrides PATH
    #   lookup). Useful when cert-grep is installed somewhere unusual.
    use_openssl: bool = False
    certgrep_path: Optional[str] = None

    # Preset name (for record-keeping)
    preset: Optional[str] = None

    # ---- (de)serialisation ----
    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "Config":
        data = json.loads(text)
        return cls(**data)

    @classmethod
    def load(cls, path: Path) -> "Config":
        if not path.exists():
            return cls()
        return cls.from_json(path.read_text())

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json() + "\n")

    # ---- preset + MVP derivation ----
    def apply_preset(self, name: str) -> None:
        if name not in PRESETS:
            raise SystemExit(f"unknown preset: {name!r}; known: {list(PRESETS)}")
        self.preset = name
        for k, v in PRESETS[name].items():
            if v is not None:
                setattr(self, k, v)

    def apply_elt_env(self) -> None:
        """--elt: explicitly read the ELT_* env vars and assert they're set.

        Note: as of v2.1.0 the module-level DEFAULT_* constants ALSO honour
        these env vars implicitly (so the script picks them up even without
        --elt). This method exists for explicit invocation — it asserts
        ELT_CERT/ELT_KEY are non-empty (fails fast if the user thinks they
        set them but didn't) and tags ra_cred_source as "elt".

        Honoured env vars (any combination):
          ELT_CERT      → ra_cert     (REQUIRED with --elt)
          ELT_KEY       → ra_key      (REQUIRED with --elt)
          ELT_CA_BUNDLE → ca_bundle   (optional; ELT_CA_CERT is a fallback)
          ELT_HOST      → ejbca_host  (optional, port appended if ELT_PORT set)
          ELT_PORT      → appended to ELT_HOST as host:port

        Other ELT_* env vars (ELT_CA_NAME, ELT_CERT_PROFILE, ELT_EE_PROFILE,
        ELT_KEY_ALGORITHM, ELT_KEY_SIZE, ELT_COUNTRY, ELT_ORGANIZATIONAL_UNIT)
        are honoured implicitly at module-load time via DEFAULT_* constants —
        no need to invoke --elt to pick them up.
        """
        h = os.environ.get("ELT_HOST")
        p = os.environ.get("ELT_PORT")
        c = os.environ.get("ELT_CERT")
        k = os.environ.get("ELT_KEY")
        # ELT_CA_BUNDLE preferred; ELT_CA_CERT honoured as a fallback so
        # pre-existing Bin/elt/ce-target.env etc keep working unchanged.
        ca = os.environ.get("ELT_CA_BUNDLE") or os.environ.get("ELT_CA_CERT")
        if not (c and k):
            raise SystemExit(
                "--elt: ELT_CERT and ELT_KEY env vars must both be set.\n"
                "Optional: ELT_CA_BUNDLE (or ELT_CA_CERT), ELT_HOST, ELT_PORT.\n"
                "Example:\n"
                "    export ELT_HOST=ejbca.home.umi.ch\n"
                "    export ELT_PORT=8443\n"
                "    export ELT_CERT=/path/to/cert.pem\n"
                "    export ELT_KEY=/path/to/key.pem\n"
                "    export ELT_CA_BUNDLE=/path/to/ca-bundle.pem"
            )
        self.ra_cert = c
        self.ra_key = k
        if ca:
            self.ca_bundle = ca
        self.ra_cred_source = "elt"
        if h:
            self.ejbca_host = f"{h}:{p}" if p else h

    def derived_summary(self) -> dict:
        """Just the derived fields, for `show` output."""
        return {
            "ejbca_host": self.ejbca_host,
            "ca_name": self.ca_name,
            "cert_profile": self.cert_profile,
            "ee_profile": self.ee_profile,
            "issuer_namespace": self.issuer_namespace,
            "pki_namespace": self.pki_namespace,
            "issuer_name": self.issuer_name,
            "clusterissuer_name": self.clusterissuer_name,
            "chart_tag": self.chart_tag,
            "cert_manager_version": self.cert_manager_version,
            "ra_cert": self.ra_cert,
            "ra_key": self.ra_key,
            "ca_bundle": self.ca_bundle,
            "ra_cred_source": self.ra_cred_source,
            "common_name": self.common_name,
            "cert_name": self.cert_name,
            "secret_name": self.secret_name,
            "duration": self.duration,
            "preset": self.preset,
        }


def _resolve_names(cfg: Config) -> tuple:
    """v2.16.0 fresh-issuance resolution. Mutates cfg.cert_name AND
    cfg.secret_name in place. Returns `(original_cert_name,
    original_secret_name)` so cmd_do can restore them before persisting
    cfg back to config.json — that way the "RANDOM" sentinels survive
    across repeated `do` invocations and each one re-resolves freshly.

    Two independent RANDOM triggers, EITHER via the cfg field directly
    OR via the env var:

      cert_name   == 'RANDOM' (or env BD_CERT_NAME=RANDOM)
      secret_name == 'RANDOM' (or env BD_SECRET_NAME=RANDOM)

    Resolution:

    - cert_name RANDOM: cfg.cert_name becomes f"{base}-{NNNN}" where
      `base` is cfg.cert_name if it's a real name (i.e., not literally
      'RANDOM'), or the dataclass default otherwise. This creates a
      brand-new Certificate object per run — guaranteed fresh
      CertificateRequest + ejbca-issuer enrollment, no reliance on
      cert-manager noticing a spec change.

    - secret_name RANDOM: cfg.secret_name is set to a suffixed form
      that PAIRS with cfg.cert_name (see below). For backward compat
      this still works alone — it mutates only the Certificate's
      spec.secretName per run, leaving the Certificate object
      identity stable.

    - When BOTH are RANDOM, the same 4-digit suffix is shared, so
      Certificate/<base>-NNNN ↔ Secret/<base>-NNNN form a matched pair
      (easy to correlate in `kubectl get certificate -A` vs
      `kubectl get secret -A`).

    - When neither is RANDOM and secret_name is empty, secret_name
      defaults to cert_name (cert-manager's default, the pre-v2.5.0
      behaviour).

    EJBCA-side: cert_name renaming does NOT change which End Entity is
    enrolled against, because we set `endEntityName: cn` on the Issuer
    (v2.13.0) — the CSR's CommonName stays as `cfg.common_name`, so
    every enrollment hits the same EE and accumulates auto-revoked
    predecessor certs (the orphan pattern the reaper picks up).
    """
    original = (cfg.cert_name, cfg.secret_name)

    cn_is_random = (
        (cfg.cert_name or "").strip().upper() == "RANDOM" or
        (os.environ.get("BD_CERT_NAME") or "").strip().upper() == "RANDOM"
    )
    sn_is_random = (
        (cfg.secret_name or "").strip().upper() == "RANDOM" or
        (os.environ.get("BD_SECRET_NAME") or "").strip().upper() == "RANDOM"
    )

    # Suffix shared between cert and secret when both RANDOM.
    suffix = None
    if cn_is_random or sn_is_random:
        import random
        suffix = f"{random.randint(0, 9999):04d}"

    # Resolve cert_name first (secret_name resolution may depend on it).
    if cn_is_random:
        # `base` = whatever the user's real cert_name is. If env put
        # "RANDOM" into cfg.cert_name, fall back to the dataclass default.
        if (cfg.cert_name or "").strip().upper() == "RANDOM":
            base = Config.__dataclass_fields__["cert_name"].default
        else:
            base = cfg.cert_name
        cfg.cert_name = f"{base}-{suffix}"

    # Resolve secret_name.
    if sn_is_random:
        # Matched pair when both RANDOM (same suffix already baked into
        # cfg.cert_name); otherwise suffix off the unchanged cert_name.
        cfg.secret_name = (cfg.cert_name if cn_is_random
                           else f"{cfg.cert_name}-{suffix}")
    elif (cfg.secret_name or "").strip() == "":
        cfg.secret_name = cfg.cert_name
    # else: cfg.secret_name already holds the user-supplied literal.

    return original


# ===========================================================================
#  Logger — console verbosity + run.log writer
# ===========================================================================

def _find_certgrep(explicit_path: Optional[str] = None) -> Optional[str]:
    """Locate the cert-grep binary. Tries: (1) explicit_path if given,
    (2) `cert-grep` on PATH, (3) `cert-grep.py` on PATH (JohnB's actual
    binary name). Returns absolute path or None."""
    if explicit_path:
        return explicit_path
    for name in ("cert-grep", "cert-grep.py"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _detect_use_openssl_from_argv() -> bool:
    """Cheap detection of `-u` / `--use-openssl` in sys.argv, used at
    format-help time (before argparse has parsed anything). Tolerates
    short-option bundling like `-uv`."""
    for arg in sys.argv[1:]:
        if arg == "--use-openssl":
            return True
        if arg.startswith("-") and not arg.startswith("--") and "u" in arg[1:]:
            return True
    return False


REQUIRED_TOOLS = ("kubectl", "helm", "openssl", "curl")


def _extract_certgrep_path_from_argv() -> Optional[str]:
    """Cheap extraction of `--certgrep PATH` (or `--certgrep=PATH`) from
    sys.argv, used at format-help time before argparse has parsed."""
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--certgrep" and i + 1 < len(args):
            return args[i + 1]
        if a.startswith("--certgrep="):
            return a.split("=", 1)[1]
    return None


def _missing_required_tools(use_openssl: bool,
                            extra_certgrep_path: Optional[str] = None) -> list:
    """Return the list of required tools that aren't on PATH. cert-grep is
    required only when `use_openssl` is False; with `-u/--use-openssl` the
    script can fall back to openssl for step 5.100, so a missing cert-grep
    doesn't contribute to the error condition."""
    missing = [t for t in REQUIRED_TOOLS if not shutil.which(t)]
    if not use_openssl and not _find_certgrep(extra_certgrep_path):
        missing.append("cert-grep")
    return missing


def _tools_inventory(extra_certgrep_path: Optional[str] = None,
                     use_openssl: Optional[bool] = None) -> str:
    """Capture absolute paths + versions of binaries we shell out to. Goes
    in the summary header so JohnB can reproduce the run from logs.

    `use_openssl=None` auto-detects from sys.argv (for the --help path,
    where argparse hasn't parsed yet); pass an explicit bool from the
    `do`/`run` paths after argparse.

    Tool table: one-line per tool (path + short version) — no inline
    cert-grep multi-line dump. The cert-grep `--version` block is emitted
    SEPARATELY after the table so its internal alignment is preserved
    (libraries-loaded confirmation).
    """
    if use_openssl is None:
        use_openssl = _detect_use_openssl_from_argv()
    bins = [("kubectl",   "version --client -o yaml"),
            ("helm",      "version --short"),
            ("openssl",   "version"),
            ("cert-grep", "--version"),
            ("curl",      "--version")]
    cert_grep_path = _find_certgrep(extra_certgrep_path)
    lines = []
    # Continuation indent aligns with the column where the path starts
    # ("  binary{:12s} = " = 2 + 12 + 3 = 17 cols). IndentingArgumentParser
    # doubles to 19 in the final rendered output.
    TARGET_WIDTH = 92
    PATH_COL = 17
    cont_indent = " " * PATH_COL
    for binary, ver_args in bins:
        path = cert_grep_path if binary == "cert-grep" else shutil.which(binary)
        if not path:
            if binary == "cert-grep" and use_openssl:
                lines.append(f"  {binary:12s} = NOT FOUND (fallback to OpenSSL)")
            else:
                lines.append(f"  {binary:12s} = NOT FOUND")
            continue
        # cert-grep's multi-line --version output goes in the separate
        # block after the table; here just show the path.
        if binary == "cert-grep":
            lines.append(f"  {binary:12s} = {path}")
            continue
        try:
            v_rc, v_out, v_err, _ = run([path] + ver_args.split(), timeout=5)
            text = (v_out or "").strip() or (v_err or "").strip()
        except Exception:
            text = ""
        if not text:
            lines.append(f"  {binary:12s} = {path}")
            continue
        first = text.splitlines()[0]
        inline = f"  {binary:12s} = {path}  ({first})"
        if len(inline) <= TARGET_WIDTH:
            lines.append(inline)
            continue
        # Long version → wrap onto continuation lines, preferring breaks at
        # " (" sub-paren boundaries (natural sentence breaks for tool versions).
        lines.append(f"  {binary:12s} = {path}")
        wrap_width = TARGET_WIDTH - PATH_COL
        # Split at " (" then re-attach "(" to all but the first fragment.
        raw = f"({first})"
        fragments = raw.split(" (")
        fragments = [fragments[0]] + ["(" + f for f in fragments[1:]]
        current = ""
        out_lines = []
        for frag in fragments:
            if not current:
                current = frag
            elif len(current) + 1 + len(frag) <= wrap_width:
                current += " " + frag
            else:
                out_lines.append(current)
                current = frag
        if current:
            out_lines.append(current)
        for ol in out_lines:
            lines.append(f"{cont_indent}{ol}")

    # Cert-grep separate block — runs cert-grep --version AFTER the table.
    # Layout per JohnB's spec:
    #   - ONE blank between the last tool row and the `$ ...` line
    #   - NO blank between the `$ ...` line and the version output
    #   - version lines indented further (4 spaces here → 6 after IAP)
    #     so they visually nest under the command line.
    if cert_grep_path:
        try:
            v_rc, v_out, v_err, _ = run([cert_grep_path, "--version"], timeout=5)
            text = (v_out or "").rstrip() or (v_err or "").rstrip()
            if text:
                lines.append("")
                lines.append(f"  $ {cert_grep_path} --version")
                emitted = False
                for ln in text.split("\n"):
                    stripped = ln.lstrip()
                    if not stripped and not emitted:
                        continue
                    lines.append(f"    {stripped}" if stripped else "")
                    emitted = True
        except Exception:
            pass
    return "\n".join(lines)


class Logger:
    DEFAULT = "default"
    VERBOSE = "verbose"
    ERRORS_ONLY = "errors-only"
    DRY_RUN = "dry-run"

    def __init__(self, mode: str, summary_path: Optional[Path] = None,
                 certgrep_path: Optional[str] = None):
        self.mode = mode
        self.summary_path = summary_path
        self.run_log = summary_path.open("w") if summary_path else None
        if self.run_log:
            # Header: version + tools inventory. Written first so the
            # summary.txt always starts with provenance info.
            self.run_log.write(f"=== deploy_ejbca_k8s.py v{__version__} ===\n\n")
            self.run_log.write("=== Tools ===\n")
            self.run_log.write(_tools_inventory(certgrep_path) + "\n\n")
            self.run_log.flush()

    def _emit(self, line: str, to_console: bool = True) -> None:
        if to_console:
            print(line)
        if self.run_log:
            self.run_log.write(line + "\n")
            self.run_log.flush()

    def header(self, line: str) -> None:
        self._emit(line, to_console=(self.mode != self.ERRORS_ONLY))

    def section(self, name: str) -> None:
        self._emit("")
        self._emit(f"== {name} ==", to_console=(self.mode != self.ERRORS_ONLY))

    def step_start(self, step_id: str, fn_name: str) -> None:
        """v2.10.0: emit the `[X.Y] fn_name` header BEFORE the step body
        runs, so any output the body produces (cmd echoes via show_last,
        status messages via _console_msg, etc.) appears UNDER its own
        step header — not above the next step's header. Previously the
        header was emitted after the body returned, which made block 5.2's
        output read as if it belonged to block 5.1.

        ERRORS_ONLY: suppresses the console header; the disk log still
        gets the legacy single-line summary from step_end()."""
        if self.mode == self.ERRORS_ONLY:
            return
        # Blank line before each [N.M] header so step boundaries stand
        # out visually. _DedupedStdout suppresses if previous output
        # already ended on a blank.
        _console_blank()
        print(f"  [{step_id}] {fn_name}")

    def step_end(self, step_id: str, fn_name: str, status: str, ms: int) -> None:
        """v2.10.0: emit the status/elapsed line AFTER the step body. On
        console this lands under the body output and visually closes
        the block. On disk (summary.txt) we still write the legacy
        single-line tabular form `[X.Y] fn_name <pad> STATUS (ms)` for
        grep-friendliness."""
        legacy_line = f"  [{step_id}] {fn_name}".ljust(55) + f"{status} ({fmt_elapsed(ms)})"
        if status == "FAIL" or self.mode != self.ERRORS_ONLY:
            # Right-justify the status to where the legacy single-line
            # step_line put it (column 55), so the closing line visually
            # caps the step block.
            print(" " * 55 + f"{status} ({fmt_elapsed(ms)})")
        # summary.txt (run_log) always gets the legacy single-line form,
        # whether or not console suppressed (ERRORS_ONLY).
        if self.run_log:
            self.run_log.write(legacy_line + "\n")
            self.run_log.flush()

    def failure_block(self, step_id: str, stderr: str, hint: Optional[str],
                      log_path: Path) -> None:
        # v2.23.0: wrap long stderr/hint lines before indenting them, so
        # the curl/openssl one-line error messages don't run off the
        # right edge of the terminal. Body width target = 80 cols total;
        # the failure block adds a 4-space indent, so wrap to 76 chars
        # of content before indenting. Continuation lines hang-indent
        # 6 spaces for visual grouping under the wrapped first line.
        stderr_text = stderr.strip() or "(empty)"
        wrapped_stderr = _wrap_block(stderr_text, width=76,
                                     subsequent_indent="      ")
        block_lines = [
            "",
            f"    ----- step {step_id} stderr -----",
            indent(wrapped_stderr, 4),
        ]
        if hint:
            wrapped_hint = _wrap_block(hint, width=76,
                                       subsequent_indent="      ")
            block_lines += [
                f"    ----- step {step_id} hint -----",
                indent(wrapped_hint, 4),
            ]
        block_lines += [
            f"    ----- full log: {log_path} -----",
        ]
        for ln in block_lines:
            self._emit(ln)

    def summary(self, results: list, output_dir: Path) -> None:
        run_count = len(results)
        ok_count = sum(1 for r in results if r.status == "OK")
        fail_count = sum(1 for r in results if r.status == "FAIL")
        warn_count = sum(1 for r in results if r.status == "WARN")
        skip_count = sum(1 for r in results if r.status == "SKIP")
        self._emit("")
        self._emit("")
        self._emit("=== Summary ===")
        self._emit(f"{run_count} steps run · {ok_count} OK · "
                   f"{warn_count} WARN · {fail_count} FAIL · {skip_count} SKIP")
        first_fail = next((r for r in results if r.status == "FAIL"), None)
        if first_fail:
            self._emit(f"First failure: step {first_fail.step_id}")
        self._emit(f"Artefacts:    {output_dir}/")
        self._emit("")

    def close(self) -> None:
        if self.run_log:
            self.run_log.close()
            self.run_log = None


# ===========================================================================
#  Step plumbing — StepContext + StepResult + decorator
# ===========================================================================

@dataclass
class StepResult:
    step_id: str
    fn_name: str
    status: str             # OK | FAIL | WARN | SKIP
    elapsed_ms: int
    exit_code: int
    stdout: str
    stderr: str
    artefacts: list
    hint: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "fn_name": self.fn_name,
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
            "exit_code": self.exit_code,
            "artefacts": [str(p) for p in self.artefacts],
            "hint": self.hint,
        }


class StepContext:
    """Passed to every step function. Provides .run(), .write_artefact(),
    .fail(hint), .warn(msg). Captures stdout/stderr/exit-codes across multiple
    sub-commands so the framework can write a coherent step_NxM.log."""

    def __init__(self, config: Config, output_dir: Path, step_id: str,
                 fn_name: str, dry_run: bool = False, proxy_env: Optional[dict] = None):
        self.config = config
        self.output_dir = output_dir
        self.step_id = step_id
        self.fn_name = fn_name
        self.dry_run = dry_run
        self.proxy_env = proxy_env or {}
        self._stdout_chunks: list = []
        self._stderr_chunks: list = []
        self._exit_codes: list = []
        self._artefacts: list = []
        self._hint: Optional[str] = None
        # Tracked across .run() calls so step bodies can echo the most
        # recent command to console (JohnB's self-contextualizing-output
        # rule). Console emission goes through .show_last().
        self._last_cmd_str: Optional[str] = None
        self._last_stdout: str = ""
        # v2.11.0: skip the leading blank inside the FIRST show_last of a
        # step — the step_start header already separates step blocks, so
        # show_last's own blank would create a double-blank between the
        # header and the first body output. Subsequent show_last calls
        # (multi-command steps like 5.100) still get their separating
        # blanks. Reset per-step because each step gets a new StepContext.
        self._first_show: bool = True
        self._t_start = time.monotonic()
        self._timeout_ms = 180_000

    def _safe_step_id(self) -> str:
        return self.step_id.replace(".", "x")

    def _phase_for_grouping(self) -> str:
        """Return the section identifier for this step under sections grouping.
        pre.* → 'pre'; '4.7' → '4'; '1' → '1'."""
        if self.step_id.startswith("pre."):
            return "pre"
        return self.step_id.split(".")[0]

    def _grouped_path(self, suffix: str) -> tuple:
        """Return (path, mode) for an artefact of the given suffix, respecting
        the configured grouping. `mode` is 'w' for per-step (steps grouping),
        'a' for grouped (sections / all).

        Only `.pem` always stays per-step (cert PEMs aren't usefully
        concatenated, and there's typically just one from step 5.100).
        Everything else (.log / .yaml / .json) follows the grouping mode.
        """
        grouping = getattr(self.config, "grouping", "all")
        if suffix == "pem" or grouping == "steps":
            return (self.output_dir / f"step_{self._safe_step_id()}.{suffix}", "w")
        if grouping == "sections":
            return (self.output_dir / f"section_{self._phase_for_grouping()}.{suffix}", "a")
        # all
        return (self.output_dir / f"all.{suffix}", "a")

    def _append_to_grouped_json(self, path: Path, entry: dict) -> None:
        """Append an entry to a grouped .json file as a JSON OBJECT keyed
        by function name (e.g., 'step_4x7_deploy_ejbca_cert_manager_external_issuer').
        Per JohnB's spec: easier to extract a specific step with
        `jq '.step_4x7_deploy_ejbca_cert_manager_external_issuer' all.json`
        than to scan an array.
        """
        existing = {}
        if path.exists():
            try:
                data = json.loads(path.read_text())
                if isinstance(data, dict):
                    existing = data
            except (json.JSONDecodeError, ValueError):
                existing = {}
        existing[self.fn_name] = entry
        path.write_text(json.dumps(existing, indent=2) + "\n")

    def run(self, cmd, *, env=None, input_data=None, timeout=180,
            cluster_local: bool = True, output_indent: int = 0) -> tuple:
        """Run a shell command. cluster_local=True unsets proxy env vars
        (mimics JohnB f_unset_proxy). `output_indent` indents the captured
        stdout in _stdout_chunks (which finalize() writes to all.log) by
        that many spaces — useful for cert-grep output where we want the
        whole block visibly nested under its `$ ...` command line."""
        merged_env = {}
        if cluster_local:
            # Unset proxy env per JohnB convention when talking to in-cluster k8s.
            merged_env.update({"HTTPS_PROXY": "", "HTTP_PROXY": "",
                               "https_proxy": "", "http_proxy": ""})
        else:
            merged_env.update(self.proxy_env)
        if env:
            merged_env.update(env)

        cmd_str = cmd_to_str(cmd)
        self._last_cmd_str = cmd_str
        if self.dry_run:
            line = f"$ {cmd_str}\n[dry-run, not executed]\n"
            self._stdout_chunks.append(line)
            self._exit_codes.append(0)
            self._last_stdout = ""
            return 0, "", "", 0

        rc, out, err, ms = run(cmd, env=merged_env, input_data=input_data,
                               timeout=timeout)
        captured = indent(out, output_indent) if output_indent else out
        self._stdout_chunks.append(f"$ {cmd_str}\n{captured}")
        if err:
            self._stderr_chunks.append(err)
        self._exit_codes.append(rc)
        self._last_stdout = out
        return rc, out, err, ms

    def show_last(self, output: Optional[str] = None, indent_n: int = 4) -> None:
        """Echo `$ <last_cmd>` to console, then the output indented by
        `indent_n + 2` (so the body visually nests under the command).

        JohnB's self-contextualizing-output rule: never print subprocess
        output to console without the producing command immediately above
        it. Step functions that previously did `print(indent(out, 4))`
        should call this instead.

        v2.3.0 layout:
        - Blank line before the `$ cmd` line (dedup'd by _DedupedStdout).
        - `$ cmd` indented by `indent_n` (default 4).
        - Body indented by `indent_n + 2` (default 6), and each *rendered*
          line truncated to CONSOLE_LINE_TRUNC chars in the console only.
          The on-disk all.log still gets the full untruncated text via
          _stdout_chunks.

        `output=None` → use the full stdout from the most recent .run().
        `output=<str>` → use that string (for tailed/filtered cases where
                         the full captured output isn't what we want on
                         console — e.g., describe-tail or grep-filter).
        """
        if not self._last_cmd_str:
            return
        # First show of this step: skip leading blank (step_start already
        # separated this step from the previous one). Subsequent shows
        # (multi-command steps): emit the blank to separate commands.
        if not self._first_show:
            _console_blank()
        self._first_show = False
        print(indent(f"$ {self._last_cmd_str}", indent_n))
        body = output if output is not None else self._last_stdout
        if not (body and body.strip()):
            return
        body_pad = " " * (indent_n + 2)
        lines = body.splitlines()
        # Strip leading + trailing purely-blank lines so there's no visual
        # gap on either side of the content. cert-grep emits both a blank
        # first line AND a blank last line by default; without trimming
        # them, the cert block has an ugly empty row before the next
        # `$ cmd` echo (or the step's closing OK/FAIL line).
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        for line in lines:
            rendered = body_pad + line
            if CONSOLE_LINE_TRUNC and len(rendered) > CONSOLE_LINE_TRUNC:
                rendered = rendered[:CONSOLE_LINE_TRUNC]
            print(rendered)

    def write_artefact(self, suffix: str, content: str) -> Path:
        """Write a step-scoped artefact, respecting the configured grouping.
        For grouped (sections/all) modes, appends with a separator header."""
        path, mode = self._grouped_path(suffix)
        if mode == "a" and path.exists():
            with path.open("a") as f:
                f.write(f"\n# ---- step {self.step_id} : {self.fn_name} ----\n")
                f.write(content if content.endswith("\n") else content + "\n")
        elif mode == "a":
            with path.open("w") as f:
                f.write(f"# ---- step {self.step_id} : {self.fn_name} ----\n")
                f.write(content if content.endswith("\n") else content + "\n")
        else:
            path.write_text(content)
        if path not in self._artefacts:
            self._artefacts.append(path)
        return path

    def set_hint(self, hint: str) -> None:
        self._hint = hint

    def finalize(self, status: str) -> StepResult:
        # Blank line between consecutive command-output blocks so multiple
        # `$ cmd ...` runs within one step are visually separated (no more
        # next-command-line butting directly against prior command's
        # output trailing line). Each chunk's trailing whitespace is
        # stripped, then re-joined with a blank-line separator.
        stdout = "\n\n".join(chunk.rstrip() for chunk in self._stdout_chunks
                             if chunk.rstrip())
        stderr = "\n\n".join(chunk.rstrip() for chunk in self._stderr_chunks
                             if chunk.rstrip())
        # .log respects grouping (steps/sections/all).
        log_path, log_mode = self._grouped_path("log")
        block = (
            f"-- step {self.step_id} : {self.fn_name} --\n"
            f"-- status: {status}  exit_codes: {self._exit_codes}\n\n"
            f"=== stdout ===\n{stdout}\n\n"
            f"=== stderr ===\n{stderr}\n"
        )
        if log_mode == "a" and log_path.exists():
            with log_path.open("a") as f:
                f.write("\n" + "=" * 70 + "\n")
                f.write(block)
        else:
            with log_path.open("w") as f:
                f.write(block)
        if log_path not in self._artefacts:
            self._artefacts.append(log_path)
        # JSON respects grouping (was per-step in v1.7.0 and earlier).
        json_path, json_mode = self._grouped_path("json")
        # build result dict
        result_dict = {
            "step_id": self.step_id,
            "fn_name": self.fn_name,
            "status": status,
            "exit_codes": self._exit_codes,
            "artefacts": [str(p) for p in self._artefacts],
            "hint": self._hint,
        }
        if json_mode == "a":
            self._append_to_grouped_json(json_path, result_dict)
        else:
            json_path.write_text(json.dumps(result_dict, indent=2) + "\n")
        if json_path not in self._artefacts:
            self._artefacts.append(json_path)
        elapsed_ms = int((time.monotonic() - self._t_start) * 1000)
        return StepResult(
            step_id=self.step_id, fn_name=self.fn_name, status=status,
            elapsed_ms=elapsed_ms,
            exit_code=self._exit_codes[-1] if self._exit_codes else 0,
            stdout=stdout, stderr=stderr,
            artefacts=self._artefacts, hint=self._hint,
        )


def _kubectl(ctx: StepContext, *args, **kwargs):
    cmd = ["kubectl"]
    if ctx.config.kube_context:
        cmd += ["--context", ctx.config.kube_context]
    cmd += list(args)
    return ctx.run(cmd, **kwargs)


def _helm(ctx: StepContext, *args, **kwargs):
    cmd = ["helm"]
    if ctx.config.kube_context:
        cmd += ["--kube-context", ctx.config.kube_context]
    cmd += list(args)
    return ctx.run(cmd, **kwargs)


# ===========================================================================
#  Pre-flight functions
# ===========================================================================

def pre_show_config(ctx: StepContext) -> str:
    """Print the resolved configuration. Analogue of JohnB kca_show."""
    summary = ctx.config.derived_summary()
    lines = ["    -- derived config --"]
    for k, v in sorted(summary.items()):
        lines.append(f"    {k:24s} = {v}")
    body = "\n".join(lines)
    print(body)
    ctx._stdout_chunks.append(body)
    return "OK"


def pre_probe_ca_name(ctx: StepContext) -> str:
    """Hit EJBCA REST /v1/ca and compare against the derived
    `certificateAuthorityName`. Fails fast with a diff if EJBCA renamed the
    CA underneath us (a class of failure where the script's templated
    name diverges from the live EJBCA's actual CA name)."""
    host = ctx.config.ejbca_host
    url = f"https://{host}/ejbca/ejbca-rest-api/v1/ca"
    cmd = [
        "curl", "-fsSL",
        "--cert", ctx.config.ra_cert,
        "--key", ctx.config.ra_key,
        "--cacert", ctx.config.ca_bundle,
        url,
    ]
    rc, out, err, _ = ctx.run(cmd, cluster_local=False)
    if rc != 0:
        # One value per labeled line. The opening URL also gets its own
        # line as data so the long form doesn't force "Check:" to land
        # at the wrap-continuation indent; it stays flush with "EJBCA".
        ctx.set_hint(
            f"EJBCA REST endpoint is unreachable:\n"
            f"      {url}\n"
            f"Check:\n"
            f"  - host:\n"
            f"      {host}\n"
            f"  - ra_cert:\n"
            f"      {ctx.config.ra_cert}\n"
            f"  - ra_key:\n"
            f"      {ctx.config.ra_key}\n"
            f"  - ca_bundle:\n"
            f"      {ctx.config.ca_bundle}\n"
            f"  - --proxy / HTTPS_PROXY if EJBCA is behind a corporate boundary."
        )
        return "FAIL"
    try:
        data = json.loads(out)
        live_names = [ca.get("name") for ca in data.get("certificate_authorities", [])]
    except (json.JSONDecodeError, AttributeError):
        ctx.set_hint(f"EJBCA /v1/ca returned non-JSON or unexpected shape:\n{out[:300]}")
        return "FAIL"
    derived = ctx.config.ca_name
    if derived in live_names:
        msg = f"    OK: derived CA name {derived!r} present on EJBCA."
        print(msg)
        ctx._stdout_chunks.append(msg)
        return "OK"
    ctx.set_hint(
        f"Derived CA name {derived!r} is NOT present on the live EJBCA.\n"
        f"Live CAs:\n  " + "\n  ".join(repr(n) for n in live_names) + "\n"
        "Either fix the derived name (--ca-name X / --preset) or rename the "
        "CA on EJBCA. Typical cause is a spaces-vs-hyphens or case mismatch "
        "between the script's templated name and the EJBCA-side display name."
    )
    return "FAIL"


# ===========================================================================
#  Step 1 & 2 — VERIFY RA role + credential
# ===========================================================================

def step_1_ejbca_ra_role(ctx: StepContext) -> str:
    """Tutorial step 1 — Configure EJBCA for cert-manager integration.

    Default mode: VERIFY that the configured RA credential resolves to
    something that can hit the EJBCA REST API. (Creating a fresh
    RA-cert-manager role + cert-manager-ra-01 member is --create-ra mode,
    not yet implemented.)
    """
    rc_cert = Path(ctx.config.ra_cert).is_file()
    rc_key = Path(ctx.config.ra_key).is_file()
    if not (rc_cert and rc_key):
        ctx.set_hint(
            f"RA credential files missing:\n"
            f"  ra_cert: {ctx.config.ra_cert} {'OK' if rc_cert else 'MISSING'}\n"
            f"  ra_key:  {ctx.config.ra_key}  {'OK' if rc_key else 'MISSING'}\n"
            "Supply via --ra-cred CERT,KEY or --elt (ELT_CERT/ELT_KEY env vars), "
            "or place the project default at Creds/elt/ce-eltadmin.{crt,key}."
        )
        return "FAIL"
    msg = f"    OK: RA credential files present.\n      cert: {ctx.config.ra_cert}\n      key:  {ctx.config.ra_key}\n      source: {ctx.config.ra_cred_source}"
    print(msg)
    ctx._stdout_chunks.append(msg)
    return "OK"


def step_2_ra_credential(ctx: StepContext) -> str:
    """Tutorial step 2 — Create key, CSR, and certificate for RA credential.

    VERIFY mode: display the RA cert's full details. Prefers cert-grep
    (richer output: algorithm, public key, X509v3 extensions including
    EKU/Key Usage which matters for RA-credential validity) over openssl,
    falling back to openssl when cert-grep is absent or --use-openssl is
    explicitly set. Same tool-selection logic as step 5.100.

    NOTE: we deliberately don't `openssl verify -CAfile ca_bundle ra_cert`
    here. In real EE deployments the EE server's TLS-trust chain
    (ca_bundle) and the RA credential's issuer chain are independent
    (e.g., LE-signed REST endpoint + EJBCA-internal RA cert), so the
    verify fails spuriously even when both credentials are correct.
    The actual auth check happens at the mTLS handshake when later
    steps make REST calls; if the RA cred is invalid for EJBCA, that
    surfaces as a 401/403 at first use (step 4.14 / 5.4 etc.).
    """
    c = ctx.config
    use_openssl = getattr(c, "use_openssl", False)
    explicit_certgrep = getattr(c, "certgrep_path", None)
    cert_grep = None if use_openssl else _find_certgrep(explicit_certgrep)

    # `ctx.run(...)` automatically captures the subprocess stdout into
    # _stdout_chunks (which finalize() writes to all.log). The `print()`
    # calls below mirror to the terminal for interactive runs only; they
    # do NOT re-append to _stdout_chunks (otherwise the cert appears
    # twice in all.log, which v1.25.0 unfortunately did).
    if cert_grep:
        # Same pattern as step 5.100: summary_0 for the headline overview
        # (issuer/subject/serial/validity), then summary_1 for the full
        # X509v3 extension dump (Key Usage / EKU / SANs — important for
        # validating an RA cred since it must have TLS Web Client Auth).
        rc, out, err, _ = ctx.run([cert_grep, c.ra_cert, "summary_0"],
                                  output_indent=4)
        if rc == 0:
            print("    OK: RA cert parses cleanly (via cert-grep).")
            ctx.show_last(out)
            rc2, out2, _, _ = ctx.run([cert_grep, c.ra_cert, "summary_1"],
                                      output_indent=4)
            if rc2 == 0:
                ctx.show_last(out2)
            return "OK"
        # cert-grep present but failed — fall through to openssl. ctx.run
        # already captured the failure into _stdout_chunks; just emit a
        # console hint.
        print(f"    cert-grep at {cert_grep!r} returned exit {rc}; "
              f"falling back to openssl")

    if not which("openssl"):
        ctx.set_hint("Neither cert-grep nor openssl available to parse the RA "
                     "cert. Install one, pass --certgrep PATH, or supply a "
                     "pre-validated cred via --ra-cred.")
        return "FAIL"
    rc, out, err, _ = ctx.run(
        ["openssl", "x509", "-in", c.ra_cert, "-noout",
         "-subject", "-issuer", "-dates"],
    )
    if rc != 0:
        ctx.set_hint(f"RA cert {c.ra_cert} failed to parse:\n{err}")
        return "FAIL"
    print("    OK: RA cert parses cleanly (via openssl).")
    ctx.show_last()
    return "OK"


# ===========================================================================
#  Step 3 — Deploy cert-manager
# ===========================================================================

def step_3x1_add_helm_repo_jetstack(ctx: StepContext) -> str:
    """Tutorial step 3.1 — Add the cert-manager helm repository."""
    rc, _, err, _ = _helm(ctx, "repo", "add", JETSTACK_REPO_NAME,
                          JETSTACK_REPO_URL, "--force-update")
    if rc != 0:
        ctx.set_hint(f"helm repo add failed: {err.strip()}")
        return "FAIL"
    return "OK"


def step_3x2_update_helm_repo_cache(ctx: StepContext) -> str:
    """Tutorial step 3.2 — Update the helm repository cache."""
    rc, _, err, _ = _helm(ctx, "repo", "update", JETSTACK_REPO_NAME)
    if rc != 0:
        ctx.set_hint(f"helm repo update failed: {err.strip()}")
        return "FAIL"
    return "OK"


def step_3x3_install_certmgr_crds(ctx: StepContext) -> str:
    """Tutorial step 3.3 — Install the cert-manager Custom Resource Definitions."""
    ver = resolve_cert_manager_version(ctx.config.cert_manager_version)
    # Persist the resolved version back to the config for downstream steps.
    ctx.config.cert_manager_version = ver
    url = CERT_MANAGER_CRDS_URL_TPL.format(ver=ver)
    rc, _, err, _ = _kubectl(ctx, "apply", "-f", url)
    if rc != 0:
        ctx.set_hint(f"kubectl apply of {url} failed: {err.strip()}")
        return "FAIL"
    return "OK"


def step_3x4_deploy_certmgr(ctx: StepContext) -> str:
    """Tutorial step 3.4 — Deploy cert-manager using helm.

    Coexistence guard: if cert-manager is already running in the cluster
    (e.g., installed by `Bin/2.2-cluster-and-cert-manager.sh` via
    `kubectl apply -f cert-manager.yaml`), helm refuses to adopt the
    pre-existing non-Helm-managed resources and fails with an
    "invalid ownership metadata" error. Detect this case and skip the
    install — the intent of the step ("cert-manager is deployed") is
    already satisfied. Override with --force-helm-cert-manager if you
    really want to attempt the upgrade.
    """
    if not getattr(ctx.config, "force_helm_cert_manager", False):
        rc_chk, out_chk, _, _ = _kubectl(ctx,
            "get", "deployment", "cert-manager", "-n", "cert-manager",
            "-o", "jsonpath={.status.availableReplicas}",
        )
        if rc_chk == 0 and out_chk.strip().isdigit() and int(out_chk.strip()) > 0:
            msg = (f"    cert-manager already deployed in namespace 'cert-manager' "
                   f"({out_chk.strip()} ready replicas). Skipping helm install to "
                   "avoid ownership conflict with a non-Helm-managed install "
                   "(e.g., Bin/2.2's `kubectl apply -f cert-manager.yaml` path).")
            _console_msg(msg)
            ctx._stdout_chunks.append(msg)
            return "OK"
    ver = ctx.config.cert_manager_version
    rc, _, err, _ = _helm(ctx,
        "upgrade", "--install", "cert-manager",
        f"{JETSTACK_REPO_NAME}/cert-manager",
        "--namespace", "cert-manager",
        "--create-namespace",
        "--version", ver,
    )
    if rc != 0:
        ctx.set_hint(
            f"helm install cert-manager failed: {err.strip()}\n"
            "If you see 'invalid ownership metadata' / 'cannot be imported into "
            "the current release', cert-manager is already installed by a "
            "non-Helm mechanism (likely kubectl apply -f). The script normally "
            "auto-detects this and skips; if you're seeing this anyway, either "
            "(a) the check missed it (file a bug), or (b) you passed "
            "--force-helm-cert-manager intentionally."
        )
        return "FAIL"
    # Wait for the deployment to be ready (best-effort, with timeout).
    _kubectl(ctx, "-n", "cert-manager", "rollout", "status",
             "deployment/cert-manager", "--timeout=90s")
    return "OK"


# ===========================================================================
#  Step 4 — Deploy EJBCA cert-manager external issuer
# ===========================================================================

def _kubectl_apply_idempotent(ctx: StepContext, yaml_text: str,
                              server_side: bool = False) -> tuple:
    """Idempotent apply. With `server_side=True`, uses kubectl's
    server-side apply (`--server-side --force-conflicts`), which dodges
    the 256KB `last-applied-configuration` annotation cap that bites on
    large CA-bundle Secrets (steps 4.3, 4.4)."""
    args = ["apply"]
    if server_side:
        args += ["--server-side", "--force-conflicts"]
    args += ["-f", "-"]
    return _kubectl(ctx, *args, input_data=yaml_text)


def _ensure_namespace(ctx: StepContext, name: str) -> tuple:
    # `kubectl create ns X --dry-run=client -o yaml | kubectl apply -f -` is idempotent.
    yaml = f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {name}\n"
    return _kubectl_apply_idempotent(ctx, yaml)


def _detect_existing_ejbca_issuer_controller(ctx: StepContext):
    """Returns (namespace, deployment_name, ready_replicas, image_tag,
    wide_rbac) if an ejbca-cert-manager-issuer controller is already deployed
    anywhere in the cluster, else None.

    `wide_rbac` is True when the controller's container args include
    `--secret-access-granted-at-cluster-level` (per the chart's
    `secretConfig.useClusterRoleForSecretAccess=true` mode, where the
    controller resolves Issuer secret references in the Issuer's own
    namespace rather than the controller's namespace).
    """
    rc_crd, _, _, _ = _kubectl(ctx,
        "get", "crd", "clusterissuers.ejbca-issuer.keyfactor.com",
        "-o", "name",
    )
    if rc_crd != 0:
        return None
    rc_d, out_d, _, _ = _kubectl(ctx,
        "get", "deployments", "-A",
        "-l", "app.kubernetes.io/name=ejbca-cert-manager-issuer",
        "-o", "jsonpath={range .items[*]}"
               "{.metadata.namespace}\t{.metadata.name}\t"
               "{.status.availableReplicas}\t"
               "{.spec.template.spec.containers[0].image}"
               "{\"\\n\"}{end}",
    )
    if rc_d != 0 or not out_d.strip():
        return None
    parts = (out_d.strip().splitlines()[0].split("\t") + ["", "", "", ""])[:4]
    ns, dep, replicas, image = parts
    installed_tag = image.rsplit(":", 1)[-1] if ":" in image else "?"
    # Probe args for the wide-RBAC flag.
    rc_a, out_a, _, _ = _kubectl(ctx,
        "get", "deployment", dep, "-n", ns,
        "-o", "jsonpath={.spec.template.spec.containers[0].args}",
    )
    wide_rbac = (rc_a == 0
                 and "--secret-access-granted-at-cluster-level" in (out_a or ""))
    return ns, dep, replicas, installed_tag, wide_rbac


def _determine_issuer_secret_namespace(ctx: StepContext) -> tuple:
    """Decide where to create the Issuer-referenced Secrets (ejbca-secret +
    ejbca-ca-secret). Returns (namespace, reason_string).

    - If an existing controller is detected with wide RBAC: pki_namespace
      (the controller will look there because Issuer is in pki_namespace).
    - If an existing controller is detected with narrow RBAC: the
      controller's own namespace (controller resolves secrets there).
    - If no existing controller: pki_namespace, because our own install at
      step 4.7 sets `--set secretConfig.useClusterRoleForSecretAccess=true`
      (wide RBAC) — see step_4x7 docstring.
    """
    existing = _detect_existing_ejbca_issuer_controller(ctx)
    if existing:
        ns, _dep, _rep, _tag, wide_rbac = existing
        if wide_rbac:
            return (ctx.config.pki_namespace,
                    f"existing controller in {ns!r} has wide RBAC "
                    "(useClusterRoleForSecretAccess=true)")
        return (ns,
                f"existing controller in {ns!r} has narrow RBAC "
                "(useClusterRoleForSecretAccess=false default); secrets must "
                "co-locate with the controller")
    return (ctx.config.pki_namespace,
            "no existing controller; our step 4.7 install will set wide RBAC")


def step_4x2_create_namespace_for_issuer(ctx: StepContext) -> str:
    """Tutorial step 4.2 — Create the namespace for the EJBCA cert-manager external issuer."""
    rc, _, err, _ = _ensure_namespace(ctx, ctx.config.issuer_namespace)
    if rc != 0:
        ctx.set_hint(f"namespace create failed: {err.strip()}")
        return "FAIL"
    return "OK"


def step_4x3_create_secret_for_ra_credential(ctx: StepContext) -> str:
    """Tutorial step 4.3 — Create the secret for the cert-manager-ra-01 credential.

    DEVIATION from the vendor tutorial: the tutorial puts secrets in the
    controller's namespace (issuer_namespace). Under
    `secretConfig.useClusterRoleForSecretAccess=true` (which our own
    step 4.7 install sets, and Twoster's Bin/2.3 chart sets) the
    controller resolves Issuer secret references in the *Issuer's*
    namespace (pki_namespace). We therefore create the secret in
    pki_namespace by default. If we detect an existing controller with
    *narrow* RBAC, we fall back to that controller's namespace so the
    secret still resolves.
    """
    ns, reason = _determine_issuer_secret_namespace(ctx)
    # Ensure the target namespace exists (idempotent; step 4.8 may re-create
    # later, which is harmless).
    rc_ns, _, err_ns, _ = _ensure_namespace(ctx, ns)
    if rc_ns != 0:
        ctx.set_hint(f"could not ensure secret namespace {ns!r}: {err_ns.strip()}")
        return "FAIL"
    msg = f"    secret namespace: {ns!r}  ({reason})"
    _console_msg(msg)
    ctx._stdout_chunks.append(msg)
    cmd_emit = [
        "kubectl", "create", "secret", "tls", "ejbca-secret",
        f"--cert={ctx.config.ra_cert}",
        f"--key={ctx.config.ra_key}",
        "-n", ns,
        "--dry-run=client", "-o", "yaml",
    ]
    rc, yaml_out, err, _ = ctx.run(cmd_emit)
    if rc != 0:
        ctx.set_hint(f"failed to render Secret YAML: {err.strip()}")
        return "FAIL"
    ctx.write_artefact("yaml", yaml_out)
    # server_side=True dodges the 256KB last-applied-configuration cap;
    # RA chains are usually small but EE-side chains have been seen
    # to push past it.
    rc2, _, err2, _ = _kubectl_apply_idempotent(ctx, yaml_out, server_side=True)
    if rc2 != 0:
        ctx.set_hint(f"kubectl apply (Secret tls) failed: {err2.strip()}")
        return "FAIL"
    return "OK"


def step_4x4_create_secret_for_ejbca_tls_chain(ctx: StepContext) -> str:
    """Tutorial step 4.4 — Create the secret for the EJBCA TLS chain.

    Same DEVIATION as step 4.3 — secret goes in pki_namespace (or detected
    controller namespace under narrow-RBAC), not issuer_namespace.
    """
    ns, _reason = _determine_issuer_secret_namespace(ctx)
    rc_ns, _, err_ns, _ = _ensure_namespace(ctx, ns)
    if rc_ns != 0:
        ctx.set_hint(f"could not ensure secret namespace {ns!r}: {err_ns.strip()}")
        return "FAIL"
    cmd_emit = [
        "kubectl", "create", "secret", "generic", "ejbca-ca-secret",
        f"--from-file=ca.crt={ctx.config.ca_bundle}",
        "-n", ns,
        "--dry-run=client", "-o", "yaml",
    ]
    rc, yaml_out, err, _ = ctx.run(cmd_emit)
    if rc != 0:
        ctx.set_hint(f"failed to render CA-chain Secret YAML: {err.strip()}")
        return "FAIL"
    ctx.write_artefact("yaml", yaml_out)
    # server_side=True is the critical one here — the CA bundle can be
    # multi-MB (e.g., Mac /etc/ssl/cert.pem) which trips the 256KB
    # last-applied-configuration cap of client-side apply (bug found by
    # JohnB during EE-side testing, 2026-05-25).
    rc2, _, err2, _ = _kubectl_apply_idempotent(ctx, yaml_out, server_side=True)
    if rc2 != 0:
        ctx.set_hint(f"kubectl apply (Secret generic) failed: {err2.strip()}")
        return "FAIL"
    return "OK"


def step_4x5_add_helm_repo_ejbca_issuer(ctx: StepContext) -> str:
    """Tutorial step 4.5 — Add the EJBCA cert-manager external issuer helm repository."""
    rc, _, err, _ = _helm(ctx, "repo", "add", EJBCA_ISSUER_REPO_NAME,
                          EJBCA_ISSUER_REPO_URL, "--force-update")
    if rc != 0:
        ctx.set_hint(f"helm repo add ejbca-issuer failed: {err.strip()}")
        return "FAIL"
    return "OK"


def step_4x6_update_helm_repo_cache(ctx: StepContext) -> str:
    """Tutorial step 4.6 — Update the helm repository cache."""
    rc, _, err, _ = _helm(ctx, "repo", "update", EJBCA_ISSUER_REPO_NAME)
    if rc != 0:
        ctx.set_hint(f"helm repo update ejbca-issuer failed: {err.strip()}")
        return "FAIL"
    return "OK"


def step_4x7_deploy_ejbca_cert_manager_external_issuer(ctx: StepContext) -> str:
    """Tutorial step 4.7 — Deploy the EJBCA cert-manager external issuer.

    DEVIATION: --set image.tag="2.2.1" instead of the chart default "1.3.2".
    Rationale: tag 1.3.2 predates PR #129 which propagates Certificate.duration
    through to EJBCA's enroll_pkcs10_certificate as end_time. See
    ../Docs2/2026-03-22.work_23.cert-manager/docs.GO/issue-128-retrospective.md.

    Coexistence guard: if another Helm release in another namespace already
    owns the cluster-scoped CRDs (e.g., Twoster's Bin/2.3 in namespace
    ejbca-issuer-system), helm upgrade --install fails with an
    "invalid ownership metadata" error on the CRD. Detect this and skip —
    the existing controller will service our Issuer/ClusterIssuer resources
    too (CRDs are cluster-scoped; the controller doesn't care which Helm
    release created the Issuer *instance*). Warn loudly if the existing
    install is at a different image tag than our pinned one, since that
    affects whether Certificate.duration is honoured.
    """
    if not getattr(ctx.config, "force_helm_ejbca_issuer", False):
        existing = _detect_existing_ejbca_issuer_controller(ctx)
        if existing:
            ns, dep, replicas, installed_tag, _wide_rbac = existing
            if installed_tag != ctx.config.chart_tag:
                msg = (
                    f"    ejbca-cert-manager-issuer already deployed in "
                    f"namespace {ns!r} (deployment {dep!r}, {replicas} "
                    f"ready, image tag {installed_tag!r}). WARNING: "
                    f"installed tag does NOT match the script's pinned "
                    f"tag {ctx.config.chart_tag!r}; per PR #129, only "
                    "v2.2.x propagates Certificate.duration to EJBCA. "
                    "Skipping helm install to avoid CRD ownership "
                    "conflict; consider upgrading the existing release."
                )
                _console_msg(msg)
                ctx._stdout_chunks.append(msg)
                ctx.set_hint(
                    f"Tag mismatch — installed: {installed_tag}, "
                    f"expected: {ctx.config.chart_tag}. Either accept the "
                    "skip (Certificates may not honour `duration`), or "
                    f"`helm upgrade ejbca-cert-manager-issuer -n {ns} "
                    f"--set image.tag={ctx.config.chart_tag}` to bump "
                    "the existing release in place."
                )
                return "WARN"
            msg = (
                f"    ejbca-cert-manager-issuer already deployed in "
                f"namespace {ns!r} (deployment {dep!r}, {replicas} "
                f"ready, image tag {installed_tag!r} matches script's "
                "pin). Skipping helm install to avoid CRD ownership "
                "conflict with the existing release."
            )
            _console_msg(msg)
            ctx._stdout_chunks.append(msg)
            return "OK"
    # Our fresh install uses wide RBAC (useClusterRoleForSecretAccess=true)
    # so Issuer secret references resolve in the Issuer's own namespace
    # rather than the controller's namespace. Matches the Bin/2.3 v2 chart
    # that Twoster upgraded to on 2026-05-25 (per bridge); avoids the
    # cross-namespace lookup gotcha entirely.
    rc, _, err, _ = _helm(ctx,
        "upgrade", "--install", "ejbca-cert-manager-issuer",
        EJBCA_ISSUER_CHART,
        "--namespace", ctx.config.issuer_namespace,
        "--set", f'image.tag={ctx.config.chart_tag}',
        "--set", "secretConfig.useClusterRoleForSecretAccess=true",
    )
    if rc != 0:
        ctx.set_hint(
            f"helm install ejbca-cert-manager-issuer failed: {err.strip()}\n"
            f"Tried: image.tag={ctx.config.chart_tag}, "
            f"namespace={ctx.config.issuer_namespace}\n"
            "If you see 'invalid ownership metadata' on a cluster-scoped CRD, "
            "another Helm release in another namespace owns it. The script "
            "normally auto-detects and skips; if you're seeing this anyway, "
            "either the probe missed it (file a bug) or you passed "
            "--force-helm-ejbca-issuer intentionally."
        )
        return "FAIL"
    return "OK"


def step_4x8_create_namespace_for_issuing_certificates(ctx: StepContext) -> str:
    """Tutorial step 4.8 — Create a namespace for issuing certificates."""
    rc, _, err, _ = _ensure_namespace(ctx, ctx.config.pki_namespace)
    if rc != 0:
        ctx.set_hint(f"namespace create ({ctx.config.pki_namespace}) failed: {err.strip()}")
        return "FAIL"
    return "OK"


_ISSUER_YAML_TPL = """apiVersion: ejbca-issuer.keyfactor.com/v1alpha1
kind: {kind}
metadata:
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: {label_name}
    app.kubernetes.io/instance: {label_instance}
    app.kubernetes.io/part-of: ejbca-issuer
    app.kubernetes.io/created-by: ejbca-issuer
  name: {name}
spec:
  hostname: "{hostname}"
  ejbcaSecretName: "ejbca-secret"
  certificateAuthorityName: "{ca_name}"
  certificateProfileName: "{cert_profile}"
  endEntityProfileName: "{ee_profile}"
  caBundleSecretName: ejbca-ca-secret
  endEntityName: cn
"""
# Note on `endEntityName: cn` (v2.13.0+): explicit binding so every
# enrollment lands on the SAME EJBCA End Entity (the one whose username
# matches the CSR's CN). Without it, ejbca-issuer falls back to its
# implicit-derivation default (tries CN → DNS → URI → IP → email in
# order), which has shifted between chart versions in the past. Locking
# it removes that ambiguity and guarantees the EE-side cert-churn
# behaviour that RANDOM-mode runs depend on for orphan generation.


def _render_issuer_yaml(ctx: StepContext, kind: str) -> str:
    is_cluster = (kind == "ClusterIssuer")
    return _ISSUER_YAML_TPL.format(
        kind=kind,
        namespace=ctx.config.pki_namespace,
        label_name=("clusterissuer" if is_cluster else "issuer"),
        label_instance=(ctx.config.clusterissuer_name if is_cluster else ctx.config.issuer_name),
        name=(ctx.config.clusterissuer_name if is_cluster else ctx.config.issuer_name),
        hostname=ctx.config.ejbca_host,
        ca_name=ctx.config.ca_name,
        cert_profile=ctx.config.cert_profile,
        ee_profile=ctx.config.ee_profile,
    )


def step_4x9_create_issuer_yaml_file(ctx: StepContext) -> str:
    """Tutorial step 4.9 — Create the issuer.yaml file."""
    yaml_text = _render_issuer_yaml(ctx, "Issuer")
    ctx.write_artefact("yaml", yaml_text)
    # v2.14.0: surface the rendered manifest inline so it serves as a
    # canonical Issuer reference for users adopting cert-manager.
    block = _console_yaml(yaml_text, "rendered Issuer YAML")
    ctx._stdout_chunks.append(block)
    return "OK"


def step_4x10_apply_issuer_yaml(ctx: StepContext) -> str:
    """Tutorial step 4.10 — Apply the issuer.yaml file."""
    yaml_text = _render_issuer_yaml(ctx, "Issuer")
    rc, _, err, _ = _kubectl_apply_idempotent(ctx, yaml_text)
    if rc != 0:
        ctx.set_hint(f"kubectl apply Issuer failed: {err.strip()}")
        return "FAIL"
    return "OK"


def step_4x11_create_clusterissuer_yaml_file(ctx: StepContext) -> str:
    """Tutorial step 4.11 — Create the clusterissuer.yaml file."""
    yaml_text = _render_issuer_yaml(ctx, "ClusterIssuer")
    ctx.write_artefact("yaml", yaml_text)
    # v2.14.0: surface the rendered manifest as canonical reference.
    block = _console_yaml(yaml_text, "rendered ClusterIssuer YAML")
    ctx._stdout_chunks.append(block)
    return "OK"


_APPROVER_RBAC_YAML = """---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-manager-controller-approve-ejbca-issuer
rules:
- apiGroups: ["cert-manager.io"]
  resources: ["signers"]
  verbs: ["approve"]
  resourceNames:
  - "issuers.ejbca-issuer.keyfactor.com/*"
  - "clusterissuers.ejbca-issuer.keyfactor.com/*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-manager-controller-approve-ejbca-issuer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-approve-ejbca-issuer
subjects:
- kind: ServiceAccount
  name: cert-manager
  namespace: cert-manager
"""


def step_4x12_apply_clusterissuer_yaml(ctx: StepContext) -> str:
    """Tutorial step 4.12 — Apply the clusterissuer.yaml, plus the approver
    RBAC bundle (otherwise ClusterIssuer-issued CRs sit forever in unapproved
    limbo; lifted from Bin/2.3-ejbca-issuer.sh:95-120)."""
    yaml_text = _render_issuer_yaml(ctx, "ClusterIssuer")
    rc, _, err, _ = _kubectl_apply_idempotent(ctx, yaml_text)
    if rc != 0:
        ctx.set_hint(f"kubectl apply ClusterIssuer failed: {err.strip()}")
        return "FAIL"
    # Also apply the approver RBAC; this is non-vendor but essential.
    rc2, _, err2, _ = _kubectl_apply_idempotent(ctx, _APPROVER_RBAC_YAML)
    if rc2 != 0:
        ctx.set_hint(f"kubectl apply approver-RBAC failed: {err2.strip()}")
        return "FAIL"
    return "OK"


def step_4x13_get_issuers(ctx: StepContext) -> str:
    """Tutorial step 4.13 — Get the issuers.ejbca-issuer.keyfactor.com."""
    rc, out, err, _ = _kubectl(ctx, "-n", ctx.config.pki_namespace,
                                "get", "issuers.ejbca-issuer.keyfactor.com")
    if rc != 0:
        ctx.set_hint(f"kubectl get issuers failed: {err.strip()}")
        return "FAIL"
    ctx.show_last()
    return "OK"


def step_4x14_describe_issuers(ctx: StepContext) -> str:
    """Tutorial step 4.14 — Describe the issuers.ejbca-issuer.keyfactor.com,
    wait for Ready: True.

    Readiness check uses jsonpath against the Ready condition's `.status`
    field, NOT substring matching on `kubectl describe` output (which has
    variable whitespace alignment and was unreliable; v1.4.0 bug, fixed
    in v1.5.0). `describe` is still run at the end for human-readable
    output (matching the tutorial's intent for this step).
    """
    if ctx.dry_run:
        return "OK"
    # Poll up to 60s for Ready=True, checking the condition directly via jsonpath.
    deadline = time.monotonic() + 60
    last_status = ""
    last_reason = ""
    last_message = ""
    while time.monotonic() < deadline:
        rc, out, _, _ = _kubectl(ctx,
            "-n", ctx.config.pki_namespace,
            "get", "issuers.ejbca-issuer.keyfactor.com", ctx.config.issuer_name,
            "-o", 'jsonpath={range .status.conditions[?(@.type=="Ready")]}'
                   '{.status}|{.reason}|{.message}{end}',
        )
        if rc == 0 and out.strip():
            parts = out.strip().split("|", 2)
            last_status = parts[0] if len(parts) > 0 else ""
            last_reason = parts[1] if len(parts) > 1 else ""
            last_message = parts[2] if len(parts) > 2 else ""
            if last_status == "True":
                # Ready — emit the descriptive output and return.
                rc_d, out_d, _, _ = _kubectl(ctx,
                    "-n", ctx.config.pki_namespace,
                    "describe", "issuers.ejbca-issuer.keyfactor.com",
                    ctx.config.issuer_name,
                )
                ctx.show_last(out_d[-1200:])
                return "OK"
        time.sleep(3)
    # Timeout — emit final describe for diagnostics, set hint.
    rc_d, out_d, _, _ = _kubectl(ctx,
        "-n", ctx.config.pki_namespace,
        "describe", "issuers.ejbca-issuer.keyfactor.com",
        ctx.config.issuer_name,
    )
    ctx.set_hint(
        f"Issuer {ctx.config.issuer_name!r} did not reach Ready=True within 60s.\n"
        f"Last observed Ready condition: status={last_status!r} "
        f"reason={last_reason!r} message={last_message!r}\n"
        f"Final describe tail:\n{indent(out_d[-1200:], 2)}\n"
        "Likely causes: (a) Issuer YAML's certificateAuthorityName doesn't "
        "match a CA on EJBCA — run `probe-ca`; (b) EJBCA REST endpoint "
        "unreachable; (c) RA credential lacks permissions; (d) Secret "
        f"reference {ctx.config.issuer_namespace!r}/ejbca-* not where "
        "controller looks (check the secret namespace messages from step "
        "4.3/4.4 output)."
    )
    return "FAIL"


# ===========================================================================
#  Step 5 — Issue certificates ("Certificate Kind Object Request")
# ===========================================================================

_CERTIFICATE_YAML_TPL = """apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: {cert_name}
  namespace: {namespace}
spec:
  duration: {duration}
  renewBefore: {renew_before}
{subject_block}  commonName: {common_name}
  privateKey:
    algorithm: {key_algorithm}
    size: {key_size}
  secretName: {secret_name}
  issuerRef:
    name: {issuer_name}
    group: ejbca-issuer.keyfactor.com
    kind: Issuer
{sans_block}"""


def _render_certificate_yaml(ctx: StepContext) -> str:
    c = ctx.config
    # Compute renewBefore as ~half of duration (cert-manager convention).
    # If duration is "1h", renewBefore = "30m". Simple heuristic.
    renew_before = "30m"
    # SANs block — only emit if there's anything to emit.
    san_lines = []
    if c.san_dns:
        san_lines.append("  dnsNames:")
        for d in c.san_dns:
            san_lines.append(f"    - {d}")
    if c.san_ip:
        san_lines.append("  ipAddresses:")
        for ip in c.san_ip:
            san_lines.append(f"    - {ip}")
    if c.san_email:
        san_lines.append("  emailAddresses:")
        for e in c.san_email:
            san_lines.append(f"    - {e}")
    sans_block = "\n".join(san_lines) + ("\n" if san_lines else "")
    # Subject block — only emit if AT LEAST ONE subject field is set.
    # Bare-CN (no subject block) is the default; matches JohnB's
    # TMP_f_cert_manager_5.txt and JohnB's ELT-Server-End-Entity profile,
    # which doesn't accept user-supplied O/C. EJBCA returns
    # "Wrong number of ORGANIZATION fields in Subject DN" if you send
    # O/C against an EE profile that doesn't allow them.
    subject_lines = []
    if c.country:
        subject_lines.append("    countries:")
        subject_lines.append(f"      - {c.country}")
    if c.organization:
        subject_lines.append("    organizations:")
        subject_lines.append(f"      - {c.organization}")
    if c.organizational_unit:
        subject_lines.append("    organizationalUnits:")
        subject_lines.append(f"      - {c.organizational_unit}")
    if subject_lines:
        subject_block = "  subject:\n" + "\n".join(subject_lines) + "\n"
    else:
        subject_block = ""
    return _CERTIFICATE_YAML_TPL.format(
        cert_name=c.cert_name,
        secret_name=c.secret_name or c.cert_name,
        namespace=c.pki_namespace,
        duration=c.duration,
        renew_before=renew_before,
        common_name=c.common_name,
        issuer_name=c.issuer_name,
        subject_block=subject_block,
        sans_block=sans_block,
        key_algorithm=c.key_algorithm,
        key_size=c.key_size,
    )


def step_5x1_create_certificate_yaml_file(ctx: StepContext) -> str:
    """Tutorial step 5.1 — Create the test-cm-02.pkirules.yaml file."""
    yaml_text = _render_certificate_yaml(ctx)
    ctx.write_artefact("yaml", yaml_text)
    # v2.14.0: surface the rendered Certificate manifest as canonical
    # reference — this is the most useful spec for users to crib from.
    block = _console_yaml(yaml_text, "rendered Certificate YAML")
    ctx._stdout_chunks.append(block)
    return "OK"


def step_5x2_apply_certificate_yaml(ctx: StepContext) -> str:
    """Tutorial step 5.2 — Apply the certificate YAML and wait briefly.

    The Secret itself is NOT created here; this step only apply's the
    Certificate object. cert-manager's controller then reconciles
    asynchronously: it creates a CertificateRequest (visible at step
    5.3), ejbca-issuer enrols against EJBCA (decision visible at 5.4),
    and only THEN does cert-manager write the issued material into the
    Secret named by spec.secretName (first visible at step 5.7).
    """
    yaml_text = _render_certificate_yaml(ctx)
    rc, _, err, _ = _kubectl_apply_idempotent(ctx, yaml_text)
    if rc != 0:
        ctx.set_hint(f"kubectl apply Certificate failed: {err.strip()}")
        return "FAIL"
    # Echo the apply command + its output so the user actually SEES
    # what just ran. First show_last in this step → no leading blank.
    ctx.show_last()
    # Blank line separates the apply's output from the parameters
    # table below — they're conceptually distinct: kubectl says what
    # it did, the table says what cert-manager will do next.
    _console_blank()
    # Tabular announcement of what cert-manager will populate.
    # Secret materialises asynchronously; first visible at step 5.7.
    secret_name = ctx.config.secret_name or ctx.config.cert_name
    table = (
        "    Secret created by cert-manager:\n"
        f"      CERT_NAME:   {ctx.config.cert_name}\n"
        f"      SECRET_NAME: {secret_name}\n"
        f"      NAMESPACE:   {ctx.config.pki_namespace}"
    )
    print(table)
    ctx._stdout_chunks.append(table)
    if not ctx.dry_run:
        time.sleep(4)   # JohnB's kca_sleep
    return "OK"


def step_5x3_list_certificate_requests(ctx: StepContext) -> str:
    """Tutorial step 5.3 — List the certificate requests."""
    rc, out, err, _ = _kubectl(ctx, "-n", ctx.config.pki_namespace,
                                "get", "CertificateRequest")
    if rc != 0:
        ctx.set_hint(f"kubectl get CertificateRequest failed: {err.strip()}")
        return "FAIL"
    ctx.show_last()
    return "OK"


def step_5x4_describe_certificate_request(ctx: StepContext) -> str:
    """Tutorial step 5.4 — Describe the most-recent CertificateRequest."""
    if ctx.dry_run:
        return "OK"
    # Find the most-recent CR for our cert_name.
    rc, out, err, _ = _kubectl(ctx, "-n", ctx.config.pki_namespace,
                                "get", "CertificateRequest",
                                "-o", "jsonpath={.items[*].metadata.name}")
    if rc != 0:
        ctx.set_hint(f"failed to list CertificateRequests: {err.strip()}")
        return "FAIL"
    matching = [n for n in out.split() if n.startswith(ctx.config.cert_name)]
    if not matching:
        ctx.set_hint(f"no CertificateRequest found for cert_name={ctx.config.cert_name!r}")
        return "FAIL"
    cr_name = sorted(matching)[-1]
    rc2, out2, err2, _ = _kubectl(ctx, "-n", ctx.config.pki_namespace,
                                   "describe", "CertificateRequest", cr_name)
    if rc2 != 0:
        ctx.set_hint(f"kubectl describe CR {cr_name} failed: {err2.strip()}")
        return "FAIL"
    ctx.show_last()
    # Look for the diagnostic pattern that signals a CA-name mismatch.
    if "doesn't exist" in out2 or "Status:         False" in out2:
        ctx.set_hint(
            "CertificateRequest is not Ready. If you see "
            '\"CA with name \\\"...\\\" doesn\'t exist\" above, the Issuer YAML\'s '
            "certificateAuthorityName doesn't match a CA on EJBCA. Run "
            "`probe-ca` to surface this earlier next time."
        )
        return "FAIL"
    return "OK"


def step_5x5_list_certificates(ctx: StepContext) -> str:
    """Tutorial step 5.5 — List the certificates created."""
    rc, out, err, _ = _kubectl(ctx, "-n", ctx.config.pki_namespace,
                                "get", "certificate")
    if rc != 0:
        ctx.set_hint(f"kubectl get certificate failed: {err.strip()}")
        return "FAIL"
    ctx.show_last()
    return "OK"


def step_5x6_describe_certificate(ctx: StepContext) -> str:
    """Tutorial step 5.6 — Describe the certificate."""
    rc, out, err, _ = _kubectl(ctx, "-n", ctx.config.pki_namespace,
                                "describe", "certificate", ctx.config.cert_name)
    if rc != 0:
        ctx.set_hint(f"kubectl describe certificate {ctx.config.cert_name} failed: {err.strip()}")
        return "FAIL"
    # Surface just the Status + Conditions block for brevity.
    lines = out.splitlines()
    if lines:
        tail_start = max(0, len(lines) - 35)
        ctx.show_last("\n".join(lines[tail_start:]))
    else:
        ctx.show_last("")
    return "OK"


def step_5x7_list_secrets(ctx: StepContext) -> str:
    """Tutorial step 5.7 — List the secrets, and explicitly call out THIS
    run's Secret (the one cert-manager populated for our Certificate).

    The Secret is created by cert-manager between step 5.2's apply and
    here; this is where it first becomes visible. We grep the listing
    for our target name and surface that line prominently so the user
    doesn't have to scan a namespace-wide listing to confirm.
    """
    rc, out, err, _ = _kubectl(ctx, "-n", ctx.config.pki_namespace, "get", "secrets")
    if rc != 0:
        ctx.set_hint(f"kubectl get secrets failed: {err.strip()}")
        return "FAIL"
    ctx.show_last()
    # Find this run's secret in the listing. `kubectl get secrets` prints
    # `NAME  TYPE  DATA  AGE` as whitespace-delimited columns; we match
    # against the first column.
    target = ctx.config.secret_name or ctx.config.cert_name
    matching = [ln for ln in out.splitlines()
                if ln.split()[:1] == [target]]
    if matching:
        msg = (f"    this run's Secret (cert-manager-created): "
               f"{matching[0].strip()}")
        # No wrap — the line is already a single kubectl row.
        _console_msg(msg, max_width=999)
        ctx._stdout_chunks.append(msg)
    elif not ctx.dry_run:
        msg = (f"    NOTE: this run's target Secret {target!r} is not yet "
               "in the listing — cert-manager may still be reconciling "
               "(check step 5.4's CertificateRequest status above).")
        _console_msg(msg)
        ctx._stdout_chunks.append(msg)
    return "OK"


def step_5x8_describe_secret(ctx: StepContext) -> str:
    """Tutorial step 5.8 — Describe the certificate's secret."""
    secret_name = ctx.config.secret_name or ctx.config.cert_name
    rc, out, err, _ = _kubectl(ctx, "-n", ctx.config.pki_namespace,
                                "describe", "secrets", secret_name)
    if rc != 0:
        ctx.set_hint(f"kubectl describe secret {secret_name} failed: {err.strip()}")
        return "FAIL"
    # The describe output is mostly metadata; show just the data-key lines so
    # the user can confirm ca.crt/tls.crt/tls.key are populated.
    keep = [line.strip() for line in out.splitlines()
            if line.strip().startswith(("ca.crt:", "tls.crt:", "tls.key:"))]
    ctx.show_last("\n".join(keep))
    return "OK"


def step_5x100_show_issued_certificate_info(ctx: StepContext) -> str:
    """Synthetic step (JohnB) — actually show the issued certificate.

    Vendor cert-issuance tutorials uniformly stop at "kubectl describe secret
    shows tls.crt is populated" but never actually show the certificate's
    contents. This step closes that gap.

    1. kubectl get certificate <name>           -- summary
    2. kubectl get Secret <name> -o json | jq -r '.data."tls.crt"' | base64 -d
                                                -- extract the PEM
    3. cert-grep (preferred) or `openssl x509 -text -noout` to render the
       human-readable cert details.
    """
    if ctx.dry_run:
        return "OK"
    c = ctx.config
    rc, out, err, _ = _kubectl(ctx, "-n", c.pki_namespace, "get", "certificate",
                                c.cert_name)
    if rc != 0:
        ctx.set_hint(f"kubectl get certificate {c.cert_name} failed: {err.strip()}")
        return "FAIL"
    ctx.show_last()

    # Extract PEM from the secret (uses secret_name, may differ from
    # cert_name when --secret-name was given as a literal override).
    secret_name = c.secret_name or c.cert_name
    rc2, out2, err2, _ = _kubectl(ctx, "-n", c.pki_namespace, "get", "Secret",
                                   secret_name, "-o", "json")
    if rc2 != 0:
        ctx.set_hint(f"kubectl get Secret {secret_name} failed: {err2.strip()}")
        return "FAIL"
    try:
        sec = json.loads(out2)
        tls_crt_b64 = sec["data"]["tls.crt"]
    except (json.JSONDecodeError, KeyError) as e:
        ctx.set_hint(f"could not extract tls.crt from secret: {e}")
        return "FAIL"
    import base64 as _b64
    pem = _b64.b64decode(tls_crt_b64).decode("ascii", errors="replace")
    pem_path = ctx.write_artefact("pem", pem)

    # Tool selection per config:
    #   --use-openssl: openssl only, FAIL if not present.
    #   --certgrep PATH: explicit cert-grep path (overrides PATH lookup).
    #   default: try cert-grep on PATH, fall back to openssl.
    use_openssl = getattr(c, "use_openssl", False)
    explicit_certgrep = getattr(c, "certgrep_path", None)
    if use_openssl:
        openssl = which("openssl")
        if not openssl:
            ctx.set_hint("--use-openssl was requested but openssl is not on PATH.")
            return "FAIL"
        return _step_5x100_openssl(ctx, pem_path, openssl)
    cert_grep = _find_certgrep(explicit_certgrep)
    if cert_grep:
        # `summary_0` for the headline overview, `summary_1` for the full
        # X509v3 detail. No `c0` selector — cert-grep auto-picks all certs
        # in the file (there's only one in step_5x100.pem anyway).
        rc3, out3, err3, _ = ctx.run(
            [cert_grep, str(pem_path), "summary_0"],
            output_indent=4,
        )
        if rc3 == 0:
            ctx.show_last(out3)
            rc4, out4, _, _ = ctx.run(
                [cert_grep, str(pem_path), "summary_1"],
                output_indent=4,
            )
            if rc4 == 0:
                ctx.show_last(out4)
            return "OK"
        # cert-grep present but failed — fall through to openssl. ctx.run
        # captured the failure already; just emit a console hint.
        print(f"    cert-grep at {cert_grep!r} returned exit {rc3}; "
              f"falling back to openssl")
    openssl = which("openssl")
    if not openssl:
        ctx.set_hint("Neither cert-grep nor openssl available; cannot show "
                     "cert details. Install one, or pass --certgrep PATH.")
        return "FAIL"
    return _step_5x100_openssl(ctx, pem_path, openssl)


def _step_5x100_openssl(ctx: StepContext, pem_path: Path, openssl: str) -> str:
    """openssl x509 -text — surface just the headline fields."""
    rc5, out5, err5, _ = ctx.run(
        [openssl, "x509", "-in", str(pem_path), "-noout", "-text"],
    )
    if rc5 != 0:
        ctx.set_hint(f"openssl x509 failed: {err5.strip()}")
        return "FAIL"
    wanted = ("Subject:", "Issuer:", "Serial Number:", "Not Before",
              "Not After", "DNS:", "IP Address:")
    keep = [line.strip() for line in out5.splitlines()
            if any(w in line for w in wanted)]
    ctx.show_last("\n".join(keep))
    return "OK"


# ===========================================================================
#  Dispatch table — the literal step IDs as strings
# ===========================================================================

STEPS = {
    "pre.show-config":   pre_show_config,
    "pre.probe-ca-name": pre_probe_ca_name,
    "1":     step_1_ejbca_ra_role,
    "2":     step_2_ra_credential,
    "3.1":   step_3x1_add_helm_repo_jetstack,
    "3.2":   step_3x2_update_helm_repo_cache,
    "3.3":   step_3x3_install_certmgr_crds,
    "3.4":   step_3x4_deploy_certmgr,
    "4.2":   step_4x2_create_namespace_for_issuer,
    "4.3":   step_4x3_create_secret_for_ra_credential,
    "4.4":   step_4x4_create_secret_for_ejbca_tls_chain,
    "4.5":   step_4x5_add_helm_repo_ejbca_issuer,
    "4.6":   step_4x6_update_helm_repo_cache,
    "4.7":   step_4x7_deploy_ejbca_cert_manager_external_issuer,
    "4.8":   step_4x8_create_namespace_for_issuing_certificates,
    "4.9":   step_4x9_create_issuer_yaml_file,
    "4.10":  step_4x10_apply_issuer_yaml,
    "4.11":  step_4x11_create_clusterissuer_yaml_file,
    "4.12":  step_4x12_apply_clusterissuer_yaml,
    "4.13":  step_4x13_get_issuers,
    "4.14":  step_4x14_describe_issuers,
    "5.1":   step_5x1_create_certificate_yaml_file,
    "5.2":   step_5x2_apply_certificate_yaml,
    "5.3":   step_5x3_list_certificate_requests,
    "5.4":   step_5x4_describe_certificate_request,
    "5.5":   step_5x5_list_certificates,
    "5.6":   step_5x6_describe_certificate,
    "5.7":   step_5x7_list_secrets,
    "5.8":   step_5x8_describe_secret,
    "5.100": step_5x100_show_issued_certificate_info,   # synthetic (JohnB)
}

# Macroscopic "phase" groupings (JohnB f_cert_manager_N analogues).
PHASES = [
    ("f_cert_manager_1", ["1"]),
    ("f_cert_manager_2", ["2"]),
    ("f_cert_manager_3", ["3.1", "3.2", "3.3", "3.4"]),
    ("f_cert_manager_4", ["4.2", "4.3", "4.4", "4.5", "4.6", "4.7",
                          "4.8", "4.9", "4.10", "4.11", "4.12", "4.13", "4.14"]),
    ("f_cert_manager_5", ["5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8",
                          "5.100"]),
]


def _phase_for(step_id: str) -> Optional[str]:
    for name, ids in PHASES:
        if step_id in ids:
            return name
    return None


# ===========================================================================
#  Subcommand handlers
# ===========================================================================

def _build_config_from_args(args, base: Optional[Config] = None) -> Config:
    """Apply CLI flags onto a Config (existing or fresh).

    Precedence (low → high): module defaults → loaded base config (if any)
    → env-var overrides → preset → --elt → individual CLI flags.

    v2.11.0: env-var overrides re-apply at every invocation, so
    `export BD_SECRET_NAME=RANDOM; bd do` works even when the saved
    config.json has `secret_name=""`. (Previously env vars only took
    effect as dataclass defaults at module load, which meant a
    saved-config secret_name="" would silently ignore the env.)
    """
    cfg = base or Config()

    # v2.11.0 + v2.16.0: re-apply env-var overrides AFTER loading base
    # config but BEFORE preset/CLI args. Non-empty env wins over saved
    # config; unset env doesn't clobber the saved value. For literal
    # values we mutate cfg directly; the special "RANDOM" sentinel is
    # left to _resolve_names() to handle, so a saved literal cert_name
    # isn't lost when env says RANDOM.
    env_cert = os.environ.get("BD_CERT_NAME")
    if env_cert and env_cert.strip().upper() != "RANDOM":
        cfg.cert_name = env_cert
    env_secret = os.environ.get("BD_SECRET_NAME")
    if env_secret and env_secret.strip().upper() != "RANDOM":
        cfg.secret_name = env_secret

    # Preset first (lowest precedence after env).
    if getattr(args, "preset", None):
        cfg.apply_preset(args.preset)

    # ELT env vars.
    if getattr(args, "elt", False):
        cfg.apply_elt_env()

    # Per-flag overrides (highest precedence).
    if getattr(args, "ra_cred", None):
        parts = args.ra_cred.split(",")
        if len(parts) != 2:
            raise SystemExit(f"--ra-cred expects CERT_PATH,KEY_PATH; got {args.ra_cred!r}")
        cfg.ra_cert, cfg.ra_key = parts
        cfg.ra_cred_source = "ra-cred"

    for fld in ("ca_name", "cert_profile", "ee_profile", "ejbca_host",
                "ca_bundle", "chart_tag", "cert_manager_version",
                "issuer_namespace", "pki_namespace",
                "issuer_name", "clusterissuer_name",
                "duration", "cert_name", "secret_name", "common_name",
                "country", "organization", "organizational_unit",
                "kube_context", "proxy", "force_helm_cert_manager",
                "grouping", "use_openssl", "certgrep",
                "key_algorithm", "key_size"):
        val = getattr(args, fld, None)
        if val is not None:
            if fld == "certgrep":
                cfg.certgrep_path = val
            else:
                setattr(cfg, fld, val)

    # If user requested ECDSA but didn't override --key-size, default
    # to 256 (P-256) instead of keeping RSA's 4096 default. Otherwise
    # cert-manager would reject `algorithm=ECDSA, size=4096` as invalid.
    if cfg.key_algorithm == "ECDSA" and getattr(args, "key_size", None) is None:
        if cfg.key_size not in (256, 384, 521):
            cfg.key_size = 256

    for list_fld in ("san_dns", "san_ip", "san_email"):
        val = getattr(args, list_fld, None)
        if val:
            setattr(cfg, list_fld, val if isinstance(val, list) else [val])

    # v2.18.0: fail fast on a malformed duration (e.g. `-d 1y` or `-d 1d`)
    # rather than wait for cert-manager's webhook to reject it at apply
    # time (step 5.2). Covers both CLI-supplied AND loaded-from-config
    # values, since validation runs after all overrides are applied.
    _validate_duration(cfg.duration)

    # v2.22.0: warn loudly when the resolved RA cred / CA bundle paths
    # don't actually exist on disk — typically the symptom of running a
    # symlinked copy of the script without ELT_* env vars set in this
    # shell. Without the warning, `bd set` silently persists fabricated
    # paths into config.json and the user only notices when step 1 fails
    # at `do` time.
    _warn_missing_cred_paths(cfg)

    return cfg


def _warn_missing_cred_paths(cfg: Config) -> None:
    """Emit a stderr warning if any of cfg.ra_cert / ra_key / ca_bundle
    point at a file that doesn't exist.

    Most common cause: the script is symlinked away from its project
    root, and the shell that invoked it doesn't have ELT_* env vars
    set. The module-load PROJECT_ROOT-relative defaults then resolve
    to paths under the script's symlink target — which has no
    `Creds/elt/` subdirectory.

    Fix shown in the warning:
      1. Set ELT_CERT / ELT_KEY / ELT_CA_BUNDLE in the env, or
      2. Pass --ra-cred CERT,KEY and --ca-bundle PATH explicitly.

    Non-blocking — the warning fires, but the run continues. Step 1
    (`ra_role`) will fail clearly at `do` time with the same hint.
    """
    missing = []
    for label, path in (("ra_cert",   cfg.ra_cert),
                        ("ra_key",    cfg.ra_key),
                        ("ca_bundle", cfg.ca_bundle)):
        if not path:
            missing.append((label, "(empty)"))
        elif not os.path.exists(path):
            missing.append((label, path))
    if not missing:
        return
    print("", file=sys.stderr)
    print("WARNING: configured credential paths do not exist on disk:",
          file=sys.stderr)
    for label, path in missing:
        print(f"    {label:10s} = {path}", file=sys.stderr)
    print("", file=sys.stderr)
    print("This usually means the script is symlinked away from its "
          "project root", file=sys.stderr)
    print("and this shell has no ELT_* env vars set. To fix, either:",
          file=sys.stderr)
    print("    export ELT_CERT=/path/to/ra.crt", file=sys.stderr)
    print("    export ELT_KEY=/path/to/ra.key", file=sys.stderr)
    print("    export ELT_CA_BUNDLE=/path/to/ca-bundle.pem", file=sys.stderr)
    print("    # (then re-run)", file=sys.stderr)
    print("", file=sys.stderr)
    print("or pass --ra-cred CERT,KEY and --ca-bundle PATH on the CLI.",
          file=sys.stderr)
    print("", file=sys.stderr)


def _resolve_output_dir(args, must_exist: bool = False) -> Path:
    """Resolve --output-dir; create timestamped subdir under default if absent.

    "Most recent" picks the dir with the latest mtime — NOT alphabetic
    sort. The alphabetic heuristic broke when named dirs sit alongside
    timestamped ones (e.g., a dev-test `test-1.9.0-shortcuts/` sorts
    AFTER any `2026-05-25_…/` because 't' > '2'); mtime correctly
    identifies the actual most-recent run regardless of naming
    convention, so named dirs from Bin/3.8 (`phase3-release-test/…/`),
    canonical references, etc. coexist cleanly with timestamped runs.
    """
    if getattr(args, "output_dir", None):
        p = Path(args.output_dir)
    else:
        # For `set` / `show` / `run` / `probe-ca` without an explicit
        # --output-dir, prefer reusing the most-recently-modified dir
        # under /tmp/claude/k8s/. (`do` does NOT call this with
        # must_exist=True any more — v2.7.0 gives each `do` its own
        # fresh timestamped dir, see cmd_do.)
        if must_exist and DEFAULT_OUTPUT_PARENT.exists():
            most_recent = _most_recent_run_dir()
            if most_recent is not None:
                return most_recent
        p = DEFAULT_OUTPUT_PARENT / now_str()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _most_recent_run_dir() -> Optional[Path]:
    """Return the most-recently-modified subdir of DEFAULT_OUTPUT_PARENT,
    or None if the parent doesn't exist or contains no subdirs.

    Mtime-based (not alphabetic), so named dirs from Bin/3.8
    (`phase3-release-test/...`), canonical refs, etc. coexist cleanly
    with timestamped runs."""
    if not DEFAULT_OUTPUT_PARENT.exists():
        return None
    existing = sorted(
        (d for d in DEFAULT_OUTPUT_PARENT.iterdir() if d.is_dir()),
        key=lambda d: d.stat().st_mtime,
    )
    return existing[-1] if existing else None


def cmd_set(args) -> int:
    """`set`: write config.json into output_dir."""
    output_dir = _resolve_output_dir(args, must_exist=False)
    # If a config.json exists in the most recent dir, load it as a base so
    # repeated `set` calls accumulate.
    cfg_path = output_dir / "config.json"
    base = Config.load(cfg_path) if cfg_path.exists() else None
    cfg = _build_config_from_args(args, base=base)
    cfg.save(cfg_path)
    # The config is small enough that dumping the full JSON here saves the
    # user a follow-up `show --full` to see what landed. Matches the layout
    # of the on-disk file (sorted keys, 2-space indent). Version banner is
    # printed centrally by main(), not here.
    print(f"config written: {cfg_path}")
    print(cfg.to_json())
    return 0


def cmd_show(args) -> int:
    """`show`: print derived config (or full JSON with --full)."""
    output_dir = _resolve_output_dir(args, must_exist=True)
    cfg_path = output_dir / "config.json"
    if not cfg_path.exists():
        print(f"no config found at {cfg_path} — run `set` first.", file=sys.stderr)
        return 2
    cfg = Config.load(cfg_path)
    if getattr(args, "full", False):
        print(cfg.to_json())
    else:
        summary = cfg.derived_summary()
        print("    -- derived config --")
        for k, v in sorted(summary.items()):
            print(f"    {k:24s} = {v}")
    return 0


def _iter_steps_in_range(from_step: Optional[str], to_step: Optional[str]):
    """Yield (step_id, fn) pairs from STEPS, filtered by --from / --to.
    Pre-flight steps (pre.*) are excluded from the range filter; they only
    run when explicitly named or via `run`."""
    keys = [k for k in STEPS.keys() if not k.startswith("pre.")]
    start_idx = 0
    end_idx = len(keys)
    if from_step:
        if from_step not in keys:
            raise SystemExit(f"--from {from_step!r}: not a known step id; known: {keys}")
        start_idx = keys.index(from_step)
    if to_step:
        if to_step not in keys:
            raise SystemExit(f"--to {to_step!r}: not a known step id; known: {keys}")
        end_idx = keys.index(to_step) + 1
    for k in keys[start_idx:end_idx]:
        yield k, STEPS[k]


def _exec_one_step(step_id: str, fn, cfg: Config, output_dir: Path,
                   dry_run: bool, proxy_env: dict, logger: Logger) -> StepResult:
    ctx = StepContext(config=cfg, output_dir=output_dir, step_id=step_id,
                      fn_name=fn.__name__, dry_run=dry_run, proxy_env=proxy_env)
    try:
        status = fn(ctx)
    except Exception as e:
        ctx.set_hint(f"unexpected exception: {e!r}")
        status = "FAIL"
    if status not in ("OK", "FAIL", "WARN", "SKIP"):
        status = "FAIL"
    return ctx.finalize(status)


def cmd_do(args) -> int:
    """`do`: run the batch of step functions, write artefacts, print summary.

    v2.7.0: each `do` invocation creates its OWN fresh timestamped output
    dir (unless --output-dir is explicitly given). The config is loaded
    from the most-recently-modified existing dir (which is normally what
    `set` just wrote, OR the prior `do`'s dir under repeated invocation),
    so chained `set; do; do; do …` keeps propagating the same config
    forward while keeping per-run artefacts (all.log/yaml/json, .pem)
    cleanly separated. RANDOM-mode orphan runs get one dir per orphan.

    The v1.22.0 set/do wall-clock-second race is still avoided: `do`
    resolves the config source via mtime (not by computing now_str()
    itself), so even if set+do straddle a second boundary, the loaded
    config comes from set's just-written dir.
    """
    if getattr(args, "output_dir", None):
        # User passed --output-dir explicitly: honour it verbatim and
        # use it as both config source and artefact destination (legacy
        # reuse behaviour, useful for scripted re-runs).
        output_dir = _resolve_output_dir(args, must_exist=False)
        source_dir = output_dir
    else:
        # Default v2.7.0 behaviour: fresh timestamped dir for THIS run's
        # artefacts; config comes from whichever existing dir is most
        # recent (set's dir on first do, prior do's dir on subsequent).
        source_dir = _most_recent_run_dir()
        output_dir = DEFAULT_OUTPUT_PARENT / now_str()
        output_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = output_dir / "config.json"
    source_cfg_path = (source_dir / "config.json") if source_dir else None
    # Load source config (if any) AND overlay args — matches cmd_set's
    # behaviour so a one-shot `do --preset local-fixes --duration 1h`
    # without a preceding `set` still works.
    base = Config.load(source_cfg_path) if (source_cfg_path and source_cfg_path.exists()) else None
    cfg = _build_config_from_args(args, base=base)
    cfg.save(cfg_path)

    # v2.16.0 fresh-issuance resolution. Mutates cfg.cert_name and
    # cfg.secret_name in place. Returns the originals so we can restore
    # them before the final save — that way config.json keeps any
    # "RANDOM" sentinel so the NEXT `do` re-resolves a fresh suffix.
    # v2.17.0: the announcement itself moved to AFTER the logger.header()
    # call below, so the output order reads naturally:
    #   1. version banner   (from main())
    #   2. === do header ===
    #   3. fresh-issuance: ... (this run's resolved names)
    pre_resolve = _resolve_names(cfg)
    cn_random_env = (os.environ.get("BD_CERT_NAME") or "").strip().upper() == "RANDOM"
    sn_random_env = (os.environ.get("BD_SECRET_NAME") or "").strip().upper() == "RANDOM"
    announce_fresh = (cn_random_env or sn_random_env
                      or (pre_resolve[0] or "").strip().upper() == "RANDOM"
                      or (pre_resolve[1] or "").strip().upper() == "RANDOM")

    # Version banner at the top of all.log (or section_pre.log under
    # grouping=sections) — preflight scripts can read the script version
    # straight from the captured log without re-invoking `--version`.
    # Truncates the target log: each `do` invocation starts a clean log
    # (subsequent steps' finalize() appends).
    grouping = getattr(cfg, "grouping", "all")
    if grouping == "all":
        log_target = output_dir / "all.log"
    elif grouping == "sections":
        log_target = output_dir / "section_pre.log"
    else:
        log_target = None
    if log_target is not None:
        banner = (f"$ deploy_ejbca_k8s.py --version\n"
                  f"  deploy_ejbca_k8s.py v{__version__}\n")
        log_target.write_text(banner)

    proxy_env = {}
    if cfg.proxy:
        proxy_env = {"HTTPS_PROXY": cfg.proxy, "HTTP_PROXY": cfg.proxy,
                     "https_proxy": cfg.proxy, "http_proxy": cfg.proxy}

    # SUPPRESS-defaulted args may be absent; use getattr with False.
    dry_run = getattr(args, "dry_run", False)
    verbose = getattr(args, "verbose", False)
    errors_only = getattr(args, "errors_only", False)
    continue_on_fail = getattr(args, "continue_on_fail", False)
    mode = (Logger.DRY_RUN if dry_run else
            Logger.VERBOSE if verbose else
            Logger.ERRORS_ONLY if errors_only else
            Logger.DEFAULT)
    logger = Logger(mode, output_dir / "summary.txt",
                    certgrep_path=cfg.certgrep_path)
    try:
        logger.header(f"=== deploy_ejbca_k8s do — output: {output_dir}/ ===")
        # v2.17.0: announce resolved cert/secret names AFTER the header
        # (was emitted before, which read as if it preceded the run rather
        # than being part of it). Only fires when RANDOM was the trigger.
        if announce_fresh:
            _console_msg(
                f"    fresh-issuance: cert_name={cfg.cert_name!r}  "
                f"secret_name={cfg.secret_name!r}"
            )

        results: list[StepResult] = []
        last_phase = None
        steps_to_run = list(_iter_steps_in_range(args.from_step, args.to_step))
        aborted = False

        for step_id, fn in steps_to_run:
            phase = _phase_for(step_id)
            if phase != last_phase and phase is not None:
                logger.section(phase)
                last_phase = phase

            if aborted and not continue_on_fail:
                # Record a SKIP result without executing. Emit header+end
                # together (no body) so the SKIP block still has the
                # v2.10.0 two-line shape.
                results.append(StepResult(
                    step_id=step_id, fn_name=fn.__name__, status="SKIP",
                    elapsed_ms=0, exit_code=0, stdout="", stderr="",
                    artefacts=[], hint="skipped after earlier failure",
                ))
                logger.step_start(step_id, fn.__name__)
                logger.step_end(step_id, fn.__name__, "SKIP", 0)
                continue

            # v2.10.0 ordering: header BEFORE body, status AFTER body.
            logger.step_start(step_id, fn.__name__)
            res = _exec_one_step(step_id, fn, cfg, output_dir,
                                 dry_run=getattr(args, "dry_run", False), proxy_env=proxy_env,
                                 logger=logger)
            results.append(res)
            logger.step_end(step_id, fn.__name__, res.status, res.elapsed_ms)
            if res.status == "FAIL":
                # Use the step's actual log artefact (varies by grouping:
                # `step_NxM.log` for grouping=steps, `section_N.log` for
                # sections, `all.log` for all). Hardcoding the per-step
                # path was wrong under non-steps grouping (v1.20.0 bug).
                log_path = next(
                    (p for p in res.artefacts if str(p).endswith(".log")),
                    output_dir / "all.log",
                )
                logger.failure_block(step_id, res.stderr, res.hint, log_path)
                aborted = True

        # Capture the run's actually-applied names BEFORE we restore the
        # originals, so the cleanup-commands block below shows the right
        # names (the resolved-suffix ones, not the "RANDOM" sentinels).
        applied_cert_name = cfg.cert_name
        applied_secret_name = cfg.secret_name
        applied_namespace = cfg.pki_namespace
        # Detect which RANDOM triggers fired (cfg-field sentinel OR env
        # var) so the cleanup-block emitter can pick the right orphan-
        # sweep recipe (Certificates+Secrets, just Secrets, etc.).
        cn_was_random = (
            (pre_resolve[0] or "").strip().upper() == "RANDOM" or
            (os.environ.get("BD_CERT_NAME") or "").strip().upper() == "RANDOM"
        )
        sn_was_random = (
            (pre_resolve[1] or "").strip().upper() == "RANDOM" or
            (os.environ.get("BD_SECRET_NAME") or "").strip().upper() == "RANDOM"
        )
        # Base for the orphan-sweep grep pattern. If cert_name was clobbered
        # to "RANDOM" by env var, use the dataclass default as the base.
        if (pre_resolve[0] or "").strip().upper() == "RANDOM":
            orphan_base = Config.__dataclass_fields__["cert_name"].default
        else:
            orphan_base = pre_resolve[0] or applied_cert_name

        # Persist any config mutations made during the run (e.g., resolved
        # cert-manager version). BUT first restore the pre-resolution
        # cert/secret names so the on-disk config keeps the "RANDOM"
        # sentinel (or whatever the user originally requested), letting
        # subsequent `do` invocations re-resolve to a fresh suffix.
        cfg.cert_name, cfg.secret_name = pre_resolve
        cfg.save(cfg_path)

        # The per-step table goes into summary.txt only (not console — Logger.summary
        # below handles the console-visible high-level counters).
        if logger.run_log:
            logger.run_log.write("\n=== Per-step results ===\n")
            logger.run_log.write(f"{'STEP':<10} {'STATUS':<6} {'ELAPSED':<10} {'FUNCTION'}\n")
            for r in results:
                logger.run_log.write(f"{r.step_id:<10} {r.status:<6} "
                                     f"{fmt_elapsed(r.elapsed_ms):<10} {r.fn_name}\n")
            logger.run_log.flush()
        logger.summary(results, output_dir)

        # Cleanup hints — exact kubectl commands to remove this run's
        # K8s artefacts. Printed after Summary so it's easy to copy
        # straight off the terminal, AND mirrored into all.log +
        # summary.txt so a later log scrape still has the commands.
        _emit_cleanup_block(applied_cert_name, applied_secret_name,
                            applied_namespace,
                            cn_random=cn_was_random,
                            sn_random=sn_was_random,
                            orphan_base=orphan_base,
                            output_dir=output_dir, logger=logger)

        exit_code = 0 if not any(r.status == "FAIL" for r in results) else 1
        return exit_code
    finally:
        logger.close()


def _emit_cleanup_block(cert_name: str, secret_name: str,
                        namespace: str, cn_random: bool, sn_random: bool,
                        orphan_base: str,
                        output_dir: Path, logger: "Logger") -> None:
    """Emit a `=== Cleanup ===` block of kubectl commands to remove this
    run's K8s artefacts. Three sinks: console, all.log (if present),
    summary.txt (logger.run_log). Each command line is prefixed `$ `
    so it's unambiguously a shell invocation.

    v2.19.0: TWO recipes per scope (this-run / all-prior-RANDOM-runs),
    matching the two real-world cleanup intents:

      Option A — Stop renewals, KEEP the issued cert material.
                 Uses `kubectl delete certificate --cascade=orphan`, so the
                 Secret is left in place (the cert continues to be valid
                 until its notAfter, but cert-manager no longer reconciles
                 the Certificate object so no more renewals fire).

      Option B — Remove EVERYTHING (Certificate AND its Secret).
                 Default cascade. Useful when the cert is no longer needed
                 anywhere and the K8s-side material should be cleared.

    EJBCA-side state (EE + revoked cert records) is NOT touched by either
    option — that's the reaper's domain. The trailing Note flags this.

    Orphan-sweep recipe (the batch section) depends on which RANDOM
    triggers fired:
      cn_random + sn_random: matched <base>-NNNN names; sweep both
                             Certificates AND Secrets.
      cn_random only:        many Certificates (each owns its own Secret);
                             Option A sweeps Certificates orphan-style,
                             Option B sweeps both.
      sn_random only:        one Certificate (already in `cert_name`),
                             many orphan Secrets accumulated; Option A
                             orphan-deletes the one Certificate, Option B
                             also deletes all matching Secrets.
      neither:               batch section omitted.
    """
    lines: list = []
    lines.append("")
    lines.append("=== Cleanup ===")
    lines.append("")
    lines.append("This run's artefacts — Option A:")
    lines.append("  -> Stop renewals, KEEP cert material in Secret.")
    lines.append(f"  $ kubectl -n {namespace} delete certificate {cert_name} --cascade=orphan")
    lines.append("")
    lines.append("This run's artefacts — Option B:")
    lines.append("  -> Remove EVERYTHING: Certificate + Secret.")
    lines.append(f"  $ kubectl -n {namespace} delete certificate {cert_name}")
    if cert_name != secret_name:
        # Non-cascade case: explicit Secret delete too (the Secret has
        # a separate name from the Certificate, so cascade won't catch it).
        lines.append(f"  $ kubectl -n {namespace} delete secret {secret_name}")

    if cn_random or sn_random:
        lines.append("")
        lines.append("─" * 70)
        if cn_random:
            # Many Certificate objects, each from its own RANDOM-mode run.
            lines.append("")
            lines.append("ALL prior RANDOM-mode runs — Option A:")
            lines.append(f"  -> Stop renewals on every '{orphan_base}-NNNN' "
                         "Certificate, keep all Secrets.")
            lines.append(f"  $ kubectl -n {namespace} get certificate -o name \\")
            lines.append(f"      | grep '^certificate\\.cert-manager\\.io/{orphan_base}-[0-9]' \\")
            lines.append(f"      | xargs -r kubectl -n {namespace} delete --cascade=orphan")
            lines.append("")
            lines.append("ALL prior RANDOM-mode runs — Option B:")
            lines.append(f"  -> Remove every '{orphan_base}-NNNN' Certificate "
                         "AND Secret.")
            lines.append(f"  $ kubectl -n {namespace} get certificate -o name \\")
            lines.append(f"      | grep '^certificate\\.cert-manager\\.io/{orphan_base}-[0-9]' \\")
            lines.append(f"      | xargs -r kubectl -n {namespace} delete")
            lines.append(f"  $ kubectl -n {namespace} get secrets -o name \\")
            lines.append(f"      | grep '^secret/{orphan_base}-[0-9]' \\")
            lines.append(f"      | xargs -r kubectl -n {namespace} delete")
        else:
            # secret-only RANDOM: one Certificate keeps recycling its
            # spec.secretName; many orphan Secrets accumulate.
            lines.append("")
            lines.append("ALL prior RANDOM-mode runs — Option A:")
            lines.append("  -> Stop renewals on the single Certificate, "
                         "keep all Secrets.")
            lines.append(f"  $ kubectl -n {namespace} delete certificate "
                         f"{orphan_base} --cascade=orphan")
            lines.append("")
            lines.append("ALL prior RANDOM-mode runs — Option B:")
            lines.append(f"  -> Remove the Certificate AND every "
                         f"'{orphan_base}-NNNN' Secret.")
            lines.append(f"  $ kubectl -n {namespace} delete certificate {orphan_base}")
            lines.append(f"  $ kubectl -n {namespace} get secrets -o name \\")
            lines.append(f"      | grep '^secret/{orphan_base}-[0-9]' \\")
            lines.append(f"      | xargs -r kubectl -n {namespace} delete")
    lines.append("")
    # Explicit literal multi-line — bypass textwrap so the exact phrasing
    # the user wants is preserved verbatim.
    lines.append("Note:")
    lines.append("  EJBCA-side End Entity + revoked-cert records persist "
                 "across all of the above:")
    lines.append("  This is a task for the new \"EJBCA reaper enhancement\".")

    block = "\n".join(lines)
    # Sink 1: console (top of the user's terminal output).
    print(block)
    # Sink 2: all.log if it exists (under grouping=all). Appended at
    # the very end so it sits below the last step's chunk.
    all_log = output_dir / "all.log"
    if all_log.exists():
        with all_log.open("a") as f:
            f.write("\n" + block + "\n")
    # Sink 3: summary.txt via the Logger's run_log.
    if logger.run_log:
        logger.run_log.write("\n" + block + "\n")
        logger.run_log.flush()


def cmd_run(args) -> int:
    """`run STEP [STEP ...]` — execute one or more specific steps by id.

    Unlike `do`, summary.txt also includes each step's captured stdout
    (kubectl/helm/openssl/cert-grep outputs) — `run` is typically used
    interactively to inspect a single step's output (e.g., `run 5.100`
    to see the issued cert details), so the summary.txt should be the
    full story, not just a status one-liner.

    Args overlay onto the loaded config so transient overrides work
    (e.g., `bd -u run 2` forces openssl for this invocation without
    persisting it to config.json).
    """
    output_dir = _resolve_output_dir(args, must_exist=True)
    cfg_path = output_dir / "config.json"
    base = Config.load(cfg_path) if cfg_path.exists() else None
    cfg = _build_config_from_args(args, base=base)

    proxy_env = {}
    if cfg.proxy:
        proxy_env = {"HTTPS_PROXY": cfg.proxy, "HTTP_PROXY": cfg.proxy,
                     "https_proxy": cfg.proxy, "http_proxy": cfg.proxy}

    logger = Logger(Logger.VERBOSE, output_dir / "summary.txt",
                    certgrep_path=cfg.certgrep_path)
    try:
        any_fail = False
        results: list[StepResult] = []
        for step_id in args.steps:
            if step_id not in STEPS:
                print(f"unknown step id: {step_id!r}; known: {list(STEPS)}",
                      file=sys.stderr)
                return 2
            fn = STEPS[step_id]
            phase = _phase_for(step_id)
            if phase:
                logger.section(phase)
            # v2.10.0 ordering: header BEFORE body, status AFTER body.
            # (v2.20.0: cmd_run was missed in the v2.10.0 sweep; fixed.)
            logger.step_start(step_id, fn.__name__)
            res = _exec_one_step(step_id, fn, cfg, output_dir,
                                 dry_run=getattr(args, "dry_run", False),
                                 proxy_env=proxy_env, logger=logger)
            results.append(res)
            logger.step_end(step_id, fn.__name__, res.status, res.elapsed_ms)
            # Stream the captured stdout into summary.txt so the user sees
            # the actual command outputs (cert-grep, kubectl, etc.). Doesn't
            # touch console (the step functions already printed there).
            if res.stdout and logger.run_log:
                logger.run_log.write("\n")
                for line in res.stdout.splitlines():
                    logger.run_log.write("    " + line + "\n")
                logger.run_log.flush()
            if res.status == "FAIL":
                # Use the step's actual log artefact (varies by grouping:
                # `step_NxM.log` for grouping=steps, `section_N.log` for
                # sections, `all.log` for all). Hardcoding the per-step
                # path was wrong under non-steps grouping (v1.20.0 bug).
                log_path = next(
                    (p for p in res.artefacts if str(p).endswith(".log")),
                    output_dir / "all.log",
                )
                logger.failure_block(step_id, res.stderr, res.hint, log_path)
                any_fail = True
        # Final summary block — same as cmd_do, for consistency.
        logger.summary(results, output_dir)
        return 1 if any_fail else 0
    finally:
        logger.close()


def cmd_probe_ca(args) -> int:
    """Standalone pre_probe_ca_name run. Args overlay onto loaded config."""
    output_dir = _resolve_output_dir(args, must_exist=True)
    cfg_path = output_dir / "config.json"
    base = Config.load(cfg_path) if cfg_path.exists() else None
    cfg = _build_config_from_args(args, base=base)
    logger = Logger(Logger.VERBOSE, output_dir / "summary.txt",
                    certgrep_path=cfg.certgrep_path)
    try:
        # v2.10.0 ordering: header BEFORE body, status AFTER body.
        # (v2.20.0: cmd_probe_ca was missed in the v2.10.0 sweep; fixed.)
        logger.step_start("pre.probe-ca-name", pre_probe_ca_name.__name__)
        res = _exec_one_step("pre.probe-ca-name", pre_probe_ca_name, cfg,
                             output_dir, dry_run=False, proxy_env={},
                             logger=logger)
        logger.step_end(res.step_id, res.fn_name, res.status, res.elapsed_ms)
        if res.status == "FAIL":
            log_path = next(
                (p for p in res.artefacts if str(p).endswith(".log")),
                output_dir / "all.log",
            )
            logger.failure_block(res.step_id, res.stderr, res.hint, log_path)
            return 1
        return 0
    finally:
        logger.close()


# ===========================================================================
#  Argparse — IndentingArgumentParser wraps every message (usage/error/help/
#  version) with 2-space indent (if multi-line) and a trailing blank line.
#  JohnB's house style: "good spacing always, for professional touch
#  readability; blank line after script output, indentation for more than
#  one line."
# ===========================================================================

class _HelpAndCheckToolsAction(argparse.Action):
    """Replacement for argparse's default _HelpAction. Prints help, then
    runs the required-tools check, and exits with rc=1 if any required
    tool is missing — so `--help` doubles as a preflight sanity check
    for tool availability (per JohnB's spec). rc=0 when all required
    tools are present. cert-grep is excluded from the check when
    -u/--use-openssl is in effect (the script can fall back to openssl)."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest,
                         default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        use_openssl = _detect_use_openssl_from_argv()
        certgrep_path = _extract_certgrep_path_from_argv()
        missing = _missing_required_tools(use_openssl, certgrep_path)
        parser.exit(1 if missing else 0)


class IndentingArgumentParser(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        if not message:
            return
        stripped = message.rstrip("\n")
        if "\n" in stripped:
            stripped = "\n".join(
                ("  " + ln) if ln else ln for ln in stripped.splitlines()
            )
        super()._print_message(stripped + "\n\n", file)

    def error(self, message):
        # argparse's default error() calls print_usage() THEN exit(message=...),
        # which produces two separate _print_message calls — each single-line,
        # so the indent heuristic above would skip both. Combine them here so
        # the (usage + error) block is treated as one multi-line message.
        combined = self.format_usage() + f"{self.prog}: error: {message}\n"
        self._print_message(combined, sys.stderr)
        sys.exit(2)

    def format_help(self) -> str:
        """Help output: version line at top, standard help body for THIS
        parser only (no subcommand inlining — use `<subcmd> --help` for
        that), tools-inventory footer at the bottom (top-level help only;
        skipped for subparsers to keep their --help compact).
        """
        parts = [f"{self.prog} v{__version__}", "", super().format_help()]
        # Only the top-level parser has subparsers — use that to detect
        # whether we should append the tools footer.
        has_subparsers = any(isinstance(a, argparse._SubParsersAction)
                             for a in self._actions)
        if has_subparsers:
            parts.append("Tools on this host:")
            parts.append(_tools_inventory())
            parts.append("")
        return "\n".join(parts) + "\n"


class CompactHelpFormatter(argparse.HelpFormatter):
    """Compact help layout per JohnB's spec:
      - _fill_text: preserve newlines in description/epilog text
        (RawDescriptionHelpFormatter-style), so multi-line descriptions
        render as written.
      - _format_usage: emit
            usage: prog
                      [-h] [-c] [-n]                ← short no-metavar grouped
                      [-g {...}]                    ← then one-per-line
                      [--kube-context KUBE_CONTEXT]
                      ...
                   {subcommands} ...                ← positional last, less indent
    """
    def __init__(self, prog):
        super().__init__(prog, max_help_position=30, width=100)

    def _fill_text(self, text, width, indent):
        return "\n".join(
            (indent + line) if line else "" for line in text.splitlines()
        )

    def _format_usage(self, usage, actions, groups, prefix):
        import re
        if prefix is None:
            prefix = "usage: "
        # Render argparse's default usage so we get correctly-bracketed
        # [token]s for each action (preserves all metavar quirks).
        default = super()._format_usage(usage, actions, groups, prefix).rstrip("\n")
        opt_tokens = re.findall(r"\[[^\]]*\]", default)
        positionals = [a for a in actions if not a.option_strings]
        pos_strs = []
        for pa in positionals:
            s = self._format_actions_usage([pa], groups).strip()
            if s:
                pos_strs.append(s)

        flag_indent = " " * 10
        pos_indent = " " * 7
        lines = [f"{prefix}{self._prog}"]
        # One flag per line — no leading-short grouping (cleaner, per JohnB).
        for tok in opt_tokens:
            lines.append(f"{flag_indent}{tok}")
        for s in pos_strs:
            lines.append(f"{pos_indent}{s}")
        # End with \n\n (matching argparse default) so there's a blank line
        # between the usage block and the description that follows.
        return "\n".join(lines) + "\n\n"


def _alpha_key(action) -> tuple:
    """Pure alphabetical sort key for an optional argument: by short letter
    (or first long-name char), case-insensitive, with uppercase-short
    tiebreaks first. Used as-is for the usage line, and as the secondary
    sort below `-h` for the options section."""
    opts = action.option_strings
    if not opts:
        return (9, "", 0, "")
    short = next((o for o in opts if len(o) == 2 and o.startswith("-")), None)
    long = next((o for o in opts if o.startswith("--")), None)
    char = short[1] if short else (long or opts[0]).lstrip("-")[0]
    primary = char.lower()
    case_break = 0 if char.isupper() else 1
    secondary = (long or opts[0]).lstrip("-").lower()
    return (1, primary, case_break, secondary)


def _action_sort_key_for_usage(action):
    """Sort key for the usage line — no special case for -h (it sorts
    alphabetically by 'h')."""
    return _alpha_key(action)


def _action_sort_key_for_options(action):
    """Sort key for the options section — -h first (conventional), then
    alphabetical."""
    opts = action.option_strings
    if opts and ("-h" in opts or "--help" in opts):
        return (0, "", 0, "")
    return _alpha_key(action)


def _sort_options_alphabetically(parser: argparse.ArgumentParser) -> None:
    """Sort optional arguments per parser, using DIFFERENT keys for the
    usage line vs the options section (per JohnB's spec):
      - parser._actions       → _action_sort_key_for_usage   (no -h special)
      - group._group_actions  → _action_sort_key_for_options (-h first)
    Also sorts each subparsers-action's _choices_actions alphabetically by
    dest, so the per-subcommand detail list reads as `do, probe-ca, run,
    set, show` (the {set,show,...} choice metavar stays in declaration
    order because that comes from action.choices, which we don't touch).
    """
    parser._actions.sort(key=_action_sort_key_for_usage)
    for group in parser._action_groups:
        if (group.title or "").lower() == "positional arguments":
            for sub_action in group._group_actions:
                if isinstance(sub_action, argparse._SubParsersAction):
                    sub_action._choices_actions.sort(
                        key=lambda a: getattr(a, "dest", "")
                    )
            continue
        group._group_actions.sort(key=_action_sort_key_for_options)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                _sort_options_alphabetically(sub)


def _make_filtered_formatter(hidden_option_strings):
    """Build a HelpFormatter subclass that omits actions whose
    option_strings intersect with `hidden_option_strings` from BOTH the
    usage line and the options section. Used on subparsers so that
    globally-inherited options (defined on the `common` parent parser)
    don't clutter `<subcommand> --help`.

    This filters at FORMAT time (no mutation of shared Action objects),
    so the action objects remain visible in the top-level --help where
    they belong."""
    hidden = frozenset(hidden_option_strings)

    def _is_hidden(action):
        return bool(getattr(action, "option_strings", None)
                    and any(o in hidden for o in action.option_strings))

    class _FilteredCompactFormatter(CompactHelpFormatter):
        def _format_action(self, action):
            if _is_hidden(action):
                return ""
            return super()._format_action(action)

        def _format_actions_usage(self, actions, groups):
            return super()._format_actions_usage(
                [a for a in actions if not _is_hidden(a)], groups,
            )

        # Python 3.12+ uses this path in the wrap-too-long branch of
        # _format_usage. Without overriding it, hidden actions slip
        # back into the usage display when the usage wraps.
        def _get_actions_usage_parts(self, actions, groups):
            return super()._get_actions_usage_parts(
                [a for a in actions if not _is_hidden(a)], groups,
            )
    return _FilteredCompactFormatter


def _apply_subparser_filter(parser: argparse.ArgumentParser,
                            hidden_option_strings: set) -> None:
    """Set a filtered formatter on each subparser so the inherited common
    options don't appear in `<subcommand> --help`."""
    filtered_cls = _make_filtered_formatter(hidden_option_strings)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                sub.formatter_class = filtered_cls


def _add_set_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--preset", choices=list(PRESETS),
                   help="apply a named preset (sets multiple fields at once)")
    p.add_argument("--ra-cred", help="CERT_PATH,KEY_PATH for explicit RA credential")
    p.add_argument("--elt", action="store_true",
                   help="read ELT_HOST/ELT_CERT/ELT_KEY env vars")
    p.add_argument("--ca-bundle", help="path to CA bundle PEM")
    p.add_argument("--ejbca-host", help="EJBCA host:port (e.g., host.k3d.internal:8443)")
    p.add_argument("--ca-name", help="EJBCA certificateAuthorityName override")
    p.add_argument("--cert-profile", help="EJBCA certificateProfileName override")
    p.add_argument("--ee-profile", help="EJBCA endEntityProfileName override")
    p.add_argument("--issuer-namespace", help=f"default: {DEFAULT_ISSUER_NAMESPACE}")
    p.add_argument("--issuer-name", help=f"default: {DEFAULT_ISSUER_NAME}")
    p.add_argument("--clusterissuer-name", help=f"default: {DEFAULT_CLUSTERISSUER_NAME}")
    p.add_argument("--chart-tag", help=f"image.tag for ejbca-cert-manager-issuer (default: {DEFAULT_CHART_TAG})")
    p.add_argument("--cert-manager-version", help="default: latest (resolved via GitHub API)")
    # --kube-context, --pki-namespace, --proxy, -g/--grouping, -u/--use-openssl
    # live on `common` (top-level parser) since v1.12.0 per JohnB's spec.
    p.add_argument("--force-helm-cert-manager", action="store_true", default=None,
                   help="override step 3.4's auto-skip when cert-manager is "
                        "already present (rarely useful — will fail with "
                        "ownership conflict if existing cert-manager wasn't "
                        "Helm-installed)")
    p.add_argument("-d", "--duration",
                   help=f"Certificate duration (default: {DEFAULT_DURATION})")
    p.add_argument("--cert-name",
                   help="Certificate object's name (also the secret name, by "
                        "default). Also via env: BD_CERT_NAME. Special value "
                        "BD_CERT_NAME='RANDOM' suffixes a 4-digit number to "
                        "the default cert_name — creates a brand-new "
                        "Certificate object per `do` run (guaranteed fresh "
                        "CertificateRequest, no reliance on spec-change "
                        "detection).")
    p.add_argument("--secret-name",
                   help="Optional: K8s name of the Secret, if not CERT_NAME. "
                        "Or 'RANDOM': suffix a 4-digit number to the "
                        "cert_name. EJBCA-side: the same EE is re-enrolled "
                        "every run (CN is unchanged), so predecessor certs "
                        "accumulate as auto-revoked orphans for the reaper "
                        "to clean. Also via env: BD_SECRET_NAME='RANDOM'. "
                        "If BOTH BD_CERT_NAME=RANDOM and BD_SECRET_NAME=RANDOM "
                        "are set, the SAME suffix is shared so cert+secret "
                        "names match (Certificate/X-NNNN ↔ Secret/X-NNNN).")
    p.add_argument("--common-name", help="Certificate commonName")
    p.add_argument("--country", help=f"default: {DEFAULT_COUNTRY}")
    p.add_argument("--organization", help=f"default: {DEFAULT_ORG!r}")
    p.add_argument("--organizational-unit", help="DN OU")
    p.add_argument("--san-dns", action="append", help="DNS SAN (repeatable)")
    p.add_argument("--san-ip", action="append", help="IP SAN (repeatable)")
    p.add_argument("--san-email", action="append", help="email SAN (repeatable)")
    p.add_argument("--key-algorithm", choices=["RSA", "ECDSA", "Ed25519"],
                   help="Certificate private key algorithm (default: RSA). "
                        "Use ECDSA for EE profiles that require EC keys.")
    p.add_argument("--key-size", type=int,
                   help="Private key size: RSA bits (2048/4096/8192) or "
                        "ECDSA curve (256=P-256, 384=P-384, 521=P-521). "
                        "Default: 4096 for RSA, 256 for ECDSA, ignored "
                        "for Ed25519.")
    p.add_argument("--certgrep",
                   help="step 5.100: explicit path to cert-grep binary "
                        "(overrides PATH lookup)")


def build_argparser() -> argparse.ArgumentParser:
    # Parent parser for options shared by every subcommand. Adding it via
    # `parents=[common]` makes `-o ...` usable both before and after the
    # subcommand name (bd -o /tmp/foo show  AND  bd show -o /tmp/foo).
    common = argparse.ArgumentParser(add_help=False)
    # `default=SUPPRESS` everywhere so when these options are inherited via
    # `parents=[common]` on a subparser AND not passed there, the subparser
    # doesn't overwrite a value already set at the top level (the classic
    # argparse-parents gotcha).
    _sup = argparse.SUPPRESS
    # Sorted alphabetically by long name for predictable --help output.
    common.add_argument("-c", "--continue-on-fail", action="store_true",
                        default=_sup,
                        help="keep going through all steps after a failure")
    common.add_argument("-n", "--dry-run", action="store_true", default=_sup,
                        help="print commands without executing")
    common.add_argument("-g", "--grouping",
                        choices=["steps", "sections", "all"], default=_sup,
                        help="artefact file grouping (default: all)")
    common.add_argument("--kube-context", default=_sup,
                        help="default: current kubectl context")
    common.add_argument("-o", "--output-dir", default=_sup,
                        help="default: /tmp/claude/k8s/<YYYY-MM-DD_HH-MM-SS>/")
    common.add_argument("--pki-namespace", default=_sup,
                        help=f"default: {DEFAULT_PKI_NAMESPACE}")
    common.add_argument("--proxy", default=_sup,
                        help="HTTPS proxy URL for EJBCA REST calls")
    common.add_argument("-u", "--use-openssl", action="store_true",
                        default=_sup,
                        help="step 5.100: force openssl (skip cert-grep)")
    common.add_argument("-v", "--verbose", action="store_true", default=_sup,
                        help="print all step stdout inline")

    p = IndentingArgumentParser(
        prog="deploy_ejbca_k8s.py",
        description=(
            'Encapsulate the Keyfactor 9.3.2 "Use EJBCA with cert-manager" tutorial\n'
            '  as one idempotent Python tool.\n'
            'See Docs2/deploy-ejbca-k8s.PROPOSAL.md for the design rationale.'
        ),
        epilog="Run `deploy_ejbca_k8s.py <subcommand> --help` for "
               "subcommand-specific options.",
        parents=[common],
        formatter_class=CompactHelpFormatter,
        add_help=False,    # we install our own help action with tool-check
    )
    p.add_argument("-h", "--help", action=_HelpAndCheckToolsAction,
                   help="show this help message and exit (rc=1 if "
                        "required tools are missing — preflight check)")
    p.add_argument("-V", "--version", action="version",
                   version=f"%(prog)s v{__version__}",
                   help="show version and exit")
    # Second parent parser holding the set-style configuration options.
    # Inherited by BOTH `set` and `do` (so a one-shot `do --preset ...` works
    # without prior `set`), without duplicating the option list. Avoids the
    # "bare options with no help text" problem you saw in v1.9.0.
    set_opts = argparse.ArgumentParser(add_help=False)
    _add_set_args(set_opts)

    sub = p.add_subparsers(dest="cmd", required=True,
                           parser_class=IndentingArgumentParser)

    def _sp(name, help_text, *extra_parents, description=None):
        """Register a subparser.

        `help_text` is the one-liner shown in the top-level `--help`
        listing of subcommands. `description` (v2.21.0) is the longer
        summary shown at the top of the subcommand's own `--help`
        output — defaults to `help_text` so old call sites still get
        something useful. Pass an explicit `description=` for any
        subcommand that deserves a richer per-command summary.

        Descriptions are wrapped to 78 chars before being passed to
        argparse — `CompactHelpFormatter._fill_text` is raw-style
        (preserves explicit newlines, doesn't wrap long lines), so
        we have to do the wrap ourselves to avoid a 300-char one-liner
        running off the terminal.
        """
        desc = description if description is not None else help_text
        desc = textwrap.fill(desc, width=78)
        sp = sub.add_parser(
            name, help=help_text, description=desc,
            parents=[common, *extra_parents],
            formatter_class=CompactHelpFormatter,
            add_help=False,
        )
        sp.add_argument("-h", "--help", action=_HelpAndCheckToolsAction,
                        help="show this help message and exit")
        return sp

    # set
    _sp("set", "set/persist configuration (kca_mvp + kca_set_* analogue)",
        set_opts,
        description=(
            "Write a config.json into a fresh timestamped output directory "
            "under /tmp/claude/k8s/ (or --output-dir). Accepts every "
            "pipeline configuration flag. Subsequent `do` / `show` / `run` "
            "invocations read this file from the most-recently-modified "
            "output directory."
        ))

    # show
    psh = _sp("show", "print resolved configuration (kca_show analogue)",
              description=(
                  "Print the resolved configuration from the most-recent "
                  "output directory. Default: derived subset only (CA name, "
                  "profile names, RA cert/key paths, EJBCA host, cert/secret "
                  "names). With --full: complete JSON dump of every field."
              ))
    psh.add_argument("--full", action="store_true",
                     help="print full config.json instead of derived-only summary")

    # do — inherits set_opts (all config options) and common (-c, -n, -v,
    # -g, -u, -o, --kube-context, --pki-namespace, --proxy). Only -f/-t/-q
    # are truly do-specific and stay here.
    pdo = _sp("do", "batch-run all steps (kca_do analogue)", set_opts,
              description=(
                  "Execute every pipeline step in order, in a fresh "
                  "timestamped output directory. Per-step status is printed "
                  "inline; failures replay full stderr with a hint pointing "
                  "at the captured log file. Use --from / --to to scope the "
                  "run (e.g. `--to 4.14` to stop before test-cert issuance). "
                  "--dry-run renders YAML to disk without touching the "
                  "cluster. A `=== Cleanup ===` block at the end lists "
                  "paste-ready kubectl commands for removing the run's "
                  "K8s artefacts."
              ))
    pdo.add_argument("-f", "--from", dest="from_step",
                     help="start at this step id (e.g., 4.7)")
    pdo.add_argument("-t", "--to", dest="to_step",
                     help="stop after this step id (e.g., 4.14)")
    pdo.add_argument("-q", "--errors-only", action="store_true",
                     help="quietest: only print failures")

    # run — inherits -n/--dry-run from common; only positional `steps` is
    # run-specific.
    prn = _sp("run", "execute one or more specific steps by id",
              description=(
                  "Execute one or more specific steps ad-hoc, in the "
                  "most-recent output directory. Typically used for "
                  "iterative inspection — `run 5.100` to re-render the "
                  "issued cert summary, `run 4.14` to re-check Issuer "
                  "readiness, `run 5.4` to re-describe the latest "
                  "CertificateRequest. Args overlay onto the loaded "
                  "config so transient overrides work."
              ))
    prn.add_argument("steps", nargs="+", help="step ids, e.g. 5.100 or 4.7 4.10")

    # probe-ca
    _sp("probe-ca", "standalone CA-rename guard (pre_probe_ca_name)",
        description=(
            "Standalone pre-flight check that queries EJBCA's /v1/ca REST "
            "endpoint and asserts the configured certificateAuthorityName "
            "actually exists on the server. Useful for catching CA-rename "
            "drift before a full `do` run — the CA-not-found error from "
            "ejbca-issuer otherwise only surfaces at step 5.4."
        ))

    # Hide the inherited common-options from each subparser's --help (via
    # a filtered formatter — does NOT mutate shared Action objects, so
    # top-level --help is unaffected). Options remain parseable on the
    # subcommand (e.g. `bd do -v` still works).
    hidden = set()
    for action in common._actions:
        hidden.update(action.option_strings)
    _apply_subparser_filter(p, hidden)
    # Sort optional arguments alphabetically per group (positionals untouched).
    _sort_options_alphabetically(p)
    return p


## _add_set_args_subset_for_do removed in v1.10.0 — `do` now inherits the
## set-options parent parser directly, so the option list with help text is
## defined exactly once (in _add_set_args) and shared.


def main(argv=None) -> int:
    args = build_argparser().parse_args(argv)
    # Required-tools check, run after argparse so --help has already exited
    # at this point (rc=0 for --help/--version regardless of tool presence).
    # cert-grep is required only when -u/--use-openssl is NOT set.
    use_openssl = bool(getattr(args, "use_openssl", False))
    extra_certgrep = getattr(args, "certgrep", None)
    missing = _missing_required_tools(use_openssl, extra_certgrep)
    if missing:
        print(f"  ERROR: required tools not found on PATH: "
              f"{', '.join(missing)}", file=sys.stderr)
        print(f"  Install them, or adjust PATH; see `{sys.argv[0]} --help` "
              "for the tools-inventory section.", file=sys.stderr)
        print(file=sys.stderr)
        return 1
    # Version banner — always the first line of any subcommand's output, so
    # the user (and any downstream log scrape) immediately sees which release
    # produced this run. `-V` / `--help` exit inside argparse and never reach
    # here, so the banner doesn't duplicate those.
    print(f"deploy_ejbca_k8s.py v{__version__}")
    dispatch = {
        "set":      cmd_set,
        "show":     cmd_show,
        "do":       cmd_do,
        "run":      cmd_run,
        "probe-ca": cmd_probe_ca,
    }
    rc = dispatch[args.cmd](args) if args.cmd in dispatch else 2
    print()    # trailing blank line per JohnB's house style
    return rc


if __name__ == "__main__":
    sys.exit(main())

