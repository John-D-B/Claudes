#!/usr/bin/env python3
"""
cert-grep.py  -  X.509 Certificate Inspector

A self-contained Python app:
Decodes X.509 and PKCS#7 certificates, PKCS#10 CSRs,
PKCS#12 containers (.p12/.pfx), Java KeyStores (.jks/.jceks), X.509 CRLs,
and private keys (RSA/EC/Ed25519/Ed448/DSA) in PEM/DER format,
and public keys (RSA/EC/Ed25519/Ed448/DSA) in PEM/DER format,
with auto-detection and nicely formatted summary output.
Private key summaries expose only safe metadata — no key material.

Copyright (c) 2026, Mountain Informatik GmbH. All rights reserved.
Original software by John Buehrer.

Requirements:
    pip install cryptography

Usage:
    $ cert-grep.py <cert_file> [options...]
    $ cat cert.pem | cert-grep.py - [options...]
"""

__version__ = "4.12.0"
__origin__  = "f_cert_grep v13.13.0 (bashrc_101_g), f_cert_grep_csr v11.1.0 (bashrc_101_f)"

import sys
import os
import re
import json
import datetime
import warnings
import base64
import hashlib
from pathlib import Path
from typing import Optional, List, Dict, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs12 as p12m
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa, x25519, x448
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography import __version__ as crypto_version
    try:
        from cryptography.utils import CryptographyDeprecationWarning
    except ImportError:
        CryptographyDeprecationWarning = DeprecationWarning
except ImportError:
    print("Error: 'cryptography' library is required.", file=sys.stderr)
    print("  pip install cryptography", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
#  OID / Name Mappings
# ---------------------------------------------------------------------------

_OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "2.5.4.12": "title", "2.5.4.42": "GN", "2.5.4.4": "SN",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "2.5.4.15": "businessCategory", "2.5.4.17": "postalCode",
    "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",
    "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
}

_SIG_ALGO_NAMES = {
    "1.2.840.113549.1.1.5":  "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.4.3.2":   "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3":   "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4":   "ecdsa-with-SHA512",
    "1.3.101.112":           "Ed25519",
    "1.3.101.113":           "Ed448",
    # PQC: ML-DSA (FIPS 204, Module-Lattice Digital Signature)
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    # PQC: SLH-DSA (FIPS 205, Stateless Hash-Based Digital Signature)
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
    # PQC experimental: CRYSTALS-Dilithium Round 3 (pre-FIPS 204)
    "1.3.6.1.4.1.2.267.7.4.4":  "Dilithium2",
    "1.3.6.1.4.1.2.267.7.6.5":  "Dilithium3",
    "1.3.6.1.4.1.2.267.7.8.7":  "Dilithium5",
    # PQC experimental: ML-DSA initial-public-draft (OQS provider)
    "1.3.9999.7.1": "ML-DSA-44-ipd",
    "1.3.9999.7.4": "ML-DSA-65-ipd",
    "1.3.9999.7.6": "ML-DSA-87-ipd",
    # PQC experimental: Falcon (OQS provider)
    "1.3.9999.3.6": "Falcon-512",
    "1.3.9999.3.9": "Falcon-1024",
}

# PQC key algorithm OID -> (name, pub_key_bytes, sig_bytes, nist_level)
_PQC_KEY_INFO = {
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44",  1312, 2420, 2),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65",  1952, 3293, 3),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87",  2592, 4627, 5),
    "2.16.840.1.101.3.4.4.1":  ("ML-KEM-512",  800,  None, 1),
    "2.16.840.1.101.3.4.4.2":  ("ML-KEM-768", 1184,  None, 3),
    "2.16.840.1.101.3.4.4.3":  ("ML-KEM-1024",1568,  None, 5),
    # Experimental: CRYSTALS-Dilithium Round 3 (pre-FIPS 204)
    "1.3.6.1.4.1.2.267.7.4.4": ("Dilithium2", 1312, 2420, 2),
    "1.3.6.1.4.1.2.267.7.6.5": ("Dilithium3", 1952, 3293, 3),
    "1.3.6.1.4.1.2.267.7.8.7": ("Dilithium5", 2592, 4627, 5),
    # Experimental: ML-DSA initial-public-draft (OQS provider)
    "1.3.9999.7.1": ("ML-DSA-44-ipd", 1312, 2420, 2),
    "1.3.9999.7.4": ("ML-DSA-65-ipd", 1952, 3293, 3),
    "1.3.9999.7.6": ("ML-DSA-87-ipd", 2592, 4627, 5),
    # Experimental: Falcon (OQS provider)
    "1.3.9999.3.6": ("Falcon-512",     897, 690,  1),
    "1.3.9999.3.9": ("Falcon-1024",   1793, 1330, 5),
}

# Hybrid certificate extension OIDs (draft-ietf-lamps-cert-binding-for-multi-auth)
_HYBRID_EXT_NAMES = {
    "2.5.29.72": "subjectAltPublicKeyInfo",
    "2.5.29.73": "altSignatureAlgorithm",
    "2.5.29.74": "altSignatureValue",
}

_EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
    "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "E-mail Protection",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.4.1.311.10.3.4": "Microsoft Encrypted File System",
    "2.5.29.37.0": "Any Extended Key Usage",
}

# Private key PEM markers → (format_label, is_encrypted)
_PRIVATE_KEY_MARKERS = {
    b"-----BEGIN PRIVATE KEY-----":           ("PKCS#8",              False),
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----": ("PKCS#8 (encrypted)",  True),
    b"-----BEGIN RSA PRIVATE KEY-----":       ("PKCS#1 (RSA)",        False),
    b"-----BEGIN EC PRIVATE KEY-----":        ("SEC1 (EC)",           False),
    b"-----BEGIN DSA PRIVATE KEY-----":       ("Traditional (DSA)",   False),
    b"-----BEGIN OPENSSH PRIVATE KEY-----":   ("OpenSSH",             False),
}

# EC curve name display mappings
_EC_CURVE_DISPLAY = {
    "secp256r1": ("prime256v1", "P-256"),
    "secp384r1": ("secp384r1",  "P-384"),
    "secp521r1": ("secp521r1",  "P-521"),
    "secp256k1": ("secp256k1",  "secp256k1"),
    "brainpoolP256r1": ("brainpoolP256r1", "brainpoolP256r1"),
    "brainpoolP384r1": ("brainpoolP384r1", "brainpoolP384r1"),
    "brainpoolP512r1": ("brainpoolP512r1", "brainpoolP512r1"),
}

# Public key PEM markers → format_label
_PUBLIC_KEY_MARKERS = {
    b"-----BEGIN PUBLIC KEY-----":       "SubjectPublicKeyInfo (PKCS#8)",
    b"-----BEGIN RSA PUBLIC KEY-----":   "PKCS#1 (RSA)",
}


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def oid_name(oid) -> str:
    d = oid.dotted_string
    if d in _OID_NAMES:
        return _OID_NAMES[d]
    n = oid._name
    return n if n and n != "Unknown OID" else d


def sig_algo_name(cert) -> str:
    d = cert.signature_algorithm_oid.dotted_string
    if d in _SIG_ALGO_NAMES:
        return _SIG_ALGO_NAMES[d]
    n = cert.signature_algorithm_oid._name
    return n if n and n != "Unknown OID" else d


def format_serial(serial: int) -> str:
    h = format(serial, "x")
    if len(h) % 2:
        h = "0" + h
    return ":".join(h[i:i+2] for i in range(0, len(h), 2))


def _get_serial(cert) -> int:
    """Access cert.serial_number with CryptographyDeprecationWarning suppressed.

    Some real-world root CAs (e.g. Hellenic Academic RootCA 2015, included in
    Ubuntu ca-certificates) have serial number 0, which newer cryptography
    library versions warn about per RFC 5280.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return cert.serial_number


def format_fp(data: bytes) -> str:
    return ":".join(f"{b:02X}" for b in data)


def format_dt(dt) -> str:
    if dt is None:
        return "N/A"
    return dt.strftime("%b %d %H:%M:%S %Y") + " GMT"


def _not_before(cert):
    """cert.not_valid_before_utc (cryptography >=42) with fallback."""
    try:
        return cert.not_valid_before_utc
    except AttributeError:
        return cert.not_valid_before


def _not_after(cert):
    """cert.not_valid_after_utc (cryptography >=42) with fallback."""
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after


def _last_update(crl):
    """crl.last_update_utc (cryptography >=42) with fallback."""
    try:
        return crl.last_update_utc
    except AttributeError:
        return crl.last_update


def _next_update(crl):
    """crl.next_update_utc (cryptography >=42) with fallback."""
    try:
        return crl.next_update_utc
    except AttributeError:
        return crl.next_update


def _revocation_date(rc):
    """rc.revocation_date_utc (cryptography >=42) with fallback."""
    try:
        return rc.revocation_date_utc
    except AttributeError:
        return rc.revocation_date


def format_dn_oneline(name: x509.Name) -> str:
    parts = []
    for attr in name:
        parts.append(f"{oid_name(attr.oid)} = {attr.value}")
    return ", ".join(parts)


def parse_dn(name: x509.Name) -> Dict[str, str]:
    result = {}
    for attr in name:
        result[oid_name(attr.oid)] = attr.value
    return result


def dn_label(name: x509.Name) -> str:
    """Return a one-line label for a DN, with the most identifying component.

    Prefers CN; falls back to O, OU, or whatever is present.  Returns the
    component tag so the caller knows what it got (e.g. "CN = Foo" or
    "O = Bar Corp [no CN]").
    """
    dn = parse_dn(name)
    if "CN" in dn:
        return f"CN = {dn['CN']}"
    for tag in ("O", "OU", "DC"):
        if tag in dn:
            return f"{tag} = {dn[tag]}  [no CN]"
    # Last resort: first attribute
    if dn:
        tag, val = next(iter(dn.items()))
        return f"{tag} = {val}  [no CN]"
    return "(empty)"


def pub_key_algo(cert) -> str:
    # Check PQC OID first (public_key() throws ValueError for unknown types)
    try:
        pk_oid = cert.public_key_algorithm_oid.dotted_string
        if pk_oid in _PQC_KEY_INFO:
            return _PQC_KEY_INFO[pk_oid][0]
        if pk_oid in _SIG_ALGO_NAMES:
            return _SIG_ALGO_NAMES[pk_oid]
    except AttributeError:
        pass

    try:
        key = cert.public_key()
    except (ValueError, UnsupportedAlgorithm):
        # Unknown key type - fall back to OID
        try:
            return _SIG_ALGO_NAMES.get(
                cert.public_key_algorithm_oid.dotted_string,
                f"Unknown ({cert.public_key_algorithm_oid.dotted_string})"
            )
        except AttributeError:
            return "Unknown"

    if isinstance(key, rsa.RSAPublicKey):          return "rsaEncryption"
    if isinstance(key, ec.EllipticCurvePublicKey): return "id-ecPublicKey"
    if isinstance(key, ed25519.Ed25519PublicKey):  return "ED25519"
    if isinstance(key, ed448.Ed448PublicKey):      return "ED448"
    if isinstance(key, dsa.DSAPublicKey):          return "dsaEncryption"
    return type(key).__name__


def pub_key_bits(cert) -> Optional[int]:
    # Check PQC OID first
    try:
        pk_oid = cert.public_key_algorithm_oid.dotted_string
        if pk_oid in _PQC_KEY_INFO:
            # Return pub key size in bits (bytes * 8)
            return _PQC_KEY_INFO[pk_oid][1] * 8
    except AttributeError:
        pass

    try:
        key = cert.public_key()
    except (ValueError, UnsupportedAlgorithm):
        return None

    if isinstance(key, rsa.RSAPublicKey):          return key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey): return key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):  return 256
    if isinstance(key, ed448.Ed448PublicKey):      return 456
    if isinstance(key, dsa.DSAPublicKey):          return key.key_size
    return None


def is_pqc_cert(cert) -> bool:
    """Check if this certificate uses a PQC public key algorithm."""
    try:
        pk_oid = cert.public_key_algorithm_oid.dotted_string
        return pk_oid in _PQC_KEY_INFO
    except AttributeError:
        return False


def pqc_key_info(cert) -> Optional[tuple]:
    """Return (name, pub_bytes, sig_bytes, nist_level) for PQC certs, or None."""
    try:
        pk_oid = cert.public_key_algorithm_oid.dotted_string
        return _PQC_KEY_INFO.get(pk_oid)
    except AttributeError:
        return None


# ---------------------------------------------------------------------------
#  Format Detection & Loading
# ---------------------------------------------------------------------------

def _normalize_password(password) -> Optional[bytes]:
    """Coerce a password argument to bytes or None.

    Accepts: None, str, bytes.  Returns bytes or None.
    """
    if password is None:
        return None
    if isinstance(password, str):
        return password.encode("utf-8")
    if isinstance(password, bytes):
        return password
    raise TypeError(f"password must be str, bytes, or None, not {type(password).__name__}")


class PasswordFile:
    """Parsed multi-entry password file for batch operations.

    File format:
        # Comment lines and blank lines are ignored.
        #
        # Mapped: <glob-pattern> <whitespace> <password>
        jdcc-client-cert.p12    Cretins-4us
        *.Lame.p12              Lame
        server-*.jks            S3cret With Spaces
        #
        # Quoted passwords (for leading/trailing spaces):
        weird-app.p12           ' begins-with-space'
        #
        # Default passwords (bare lines, no glob pattern):
        # Tried in order for any file without a mapped match.
        changeit
        mypass99
        'a default with spaces'

    Parsing rules:
        1. Strip, skip blank lines and # comments.
        2. Entire line quoted (single or double) → default password, quotes stripped.
        3. No whitespace in line → default password (bare word).
        4. Otherwise → split on first whitespace run:
           before = glob pattern, after = password.
        5. If password portion is quoted → strip outer quotes.
    """

    def __init__(self, mappings: list, defaults: list):
        self.mappings = mappings   # [(glob_pattern, password), ...]
        self.defaults = defaults   # [password, ...]

    def resolve(self, filename: str) -> list:
        """Return list of passwords to try for this filename, in order."""
        import fnmatch
        basename = os.path.basename(filename)
        # Check mapped patterns (first match wins)
        for pattern, pw in self.mappings:
            if fnmatch.fnmatch(basename, pattern):
                return [pw]
        # Fall back to defaults in file order
        return list(self.defaults)

    def __repr__(self):
        return (f"PasswordFile(mappings={len(self.mappings)}, "
                f"defaults={len(self.defaults)})")


def _strip_quotes(s: str) -> str:
    """Strip matching outer single or double quotes."""
    if len(s) >= 2:
        if (s[0] == "'" and s[-1] == "'") or (s[0] == '"' and s[-1] == '"'):
            return s[1:-1]
    return s


def _parse_password_file(path: str) -> "PasswordFile":
    """Parse a multi-entry password file.

    Returns a PasswordFile with mappings and defaults.
    """
    mappings = []
    defaults = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.rstrip("\n\r")
                stripped = line.strip()
                # Skip blank lines and comments
                if not stripped or stripped.startswith("#"):
                    continue
                # Entire line quoted → default password
                if ((stripped.startswith("'") and stripped.endswith("'")) or
                        (stripped.startswith('"') and stripped.endswith('"'))):
                    defaults.append(_strip_quotes(stripped))
                    continue
                # No whitespace → default password (bare word)
                if not re.search(r'\s', stripped):
                    defaults.append(stripped)
                    continue
                # Split on first whitespace run: pattern + password
                m = re.match(r'^(\S+)\s+(.+)$', stripped)
                if m:
                    pattern = m.group(1)
                    pw = _strip_quotes(m.group(2))
                    mappings.append((pattern, pw))
                else:
                    # Shouldn't happen, but treat as default
                    defaults.append(stripped)
    except FileNotFoundError:
        print(f"- Error: password file not found: {path}", file=sys.stderr)
        sys.exit(4)
    except Exception as e:
        print(f"- Error reading password file: {e}", file=sys.stderr)
        sys.exit(4)
    return PasswordFile(mappings, defaults)


def try_b64_decode(data: bytes) -> Optional[bytes]:
    try:
        cleaned = data.strip()
        if b"-----BEGIN " in cleaned:
            return None
        # Strip surrounding double-quotes produced by jq (e.g. jq '.spec.request')
        # so that pipelines like: kubectl ... | jq '.spec.request' | cert-grep -
        # work without a sed step to remove the quotes.
        if cleaned.startswith(b'"') and cleaned.endswith(b'"'):
            cleaned = cleaned[1:-1].strip()
        stripped = re.sub(rb'\s+', b'', cleaned)
        decoded = base64.b64decode(stripped, validate=True)
        if len(decoded) < len(cleaned):
            return decoded
    except Exception:
        pass
    return None


def _try_json_unwrap(data: bytes) -> Optional[bytes]:
    """If data looks like a JSON-quoted PEM string, unwrap it.

    REST APIs (HashiCorp Vault, ACME, CGW /api/demo via jq, etc.)
    return PEM certificates as JSON strings where newlines are the
    two-character escape ``\\n`` and the value is wrapped in quotes.
    This function detects and reverses that encoding so the PEM
    data can be parsed normally.

    Returns the unwrapped bytes if all three conditions are met:
      1. Input starts with ``"``
      2. Input ends with ``"``
      3. Input contains a PEM marker (``-----BEGIN ``)

    Returns None if the input doesn't match (no change needed).
    Safe: no legitimate PEM, DER, or PKCS#12 file starts with ``"``.
    """
    text = data.strip()
    if not (text.startswith(b'"') and text.endswith(b'"')
            and b'-----BEGIN ' in text):
        return None
    text = text[1:-1]                         # strip surrounding quotes
    text = text.replace(b'\\n', b'\n')        # unescape newlines
    text = text.replace(b'\\r', b'')          # drop escaped \r
    text = text.replace(b'\\t', b'')          # drop escaped tabs
    return text


# Kubernetes resource kinds and the field paths that carry PKI data.
# Each entry: (kind_match, field_accessor, display_label)
# kind_match=None means "any kind" (e.g. generic Secret handling).
# field_accessor receives the parsed JSON object and returns a base64 string or None.
_K8S_PKI_FIELDS: List[Tuple] = [
    ("CertificateRequest", lambda o: o.get("spec", {}).get("request"),              "spec.request"),
    ("CertificateRequest", lambda o: o.get("status", {}).get("certificate"),        "status.certificate"),
    ("CertificateRequest", lambda o: o.get("status", {}).get("ca"),                 "status.ca"),
    ("Certificate",        lambda o: o.get("status", {}).get("certificate"),        "status.certificate"),
    (None,                 lambda o: o.get("data", {}).get("tls.crt"),              "data[tls.crt]"),
    (None,                 lambda o: o.get("data", {}).get("tls.key"),              "data[tls.key]"),
    (None,                 lambda o: o.get("data", {}).get("ca.crt"),               "data[ca.crt]"),
]


def _extract_pki_from_k8s_resource(obj: dict, prefix: str = "") -> List[Tuple[str, bytes]]:
    """Extract PKI items from a single K8s resource dict.

    Returns a list of (label, raw_bytes) tuples where raw_bytes is the
    decoded (DER or PEM) content ready for cert_grep() processing.
    """
    kind = obj.get("kind", "")
    name = obj.get("metadata", {}).get("name", "")
    namespace = obj.get("metadata", {}).get("namespace", "")
    results = []
    for field_kind, accessor, field_label in _K8S_PKI_FIELDS:
        if field_kind and field_kind != kind:
            continue
        value = accessor(obj)
        if not value:
            continue
        try:
            raw = base64.b64decode(value)
        except Exception:
            continue
        # Build a human-readable label: "ns/name: field" or just "name: field"
        if name and namespace:
            label = f"{namespace}/{name}: {prefix}{field_label}"
        elif name:
            label = f"{name}: {prefix}{field_label}"
        else:
            label = f"{prefix}{field_label}"
        results.append((label, raw))
    return results


def _try_k8s_json_extract(data: bytes) -> Optional[List[Tuple[str, bytes]]]:
    """Try to extract PKI objects from Kubernetes resource JSON.

    Accepts a single resource object (``{...}``) or a ``List`` resource
    (``kubectl get ... -o json`` with multiple items).

    Returns a list of ``(label, raw_bytes)`` tuples — one per PKI field
    found — or ``None`` if the input is not recognisable K8s JSON.

    Safe: only fires when the input starts with ``{`` or ``[``, and only
    extracts from the explicit whitelist ``_K8S_PKI_FIELDS``.  Unknown
    JSON objects with no matching fields return ``None`` (not an empty
    list) so the caller can fall through to normal error handling.
    """
    text = data.strip()
    if not (text.startswith(b"{") or text.startswith(b"[")):
        return None
    try:
        obj = json.loads(text)
    except Exception:
        return None

    items_to_scan = []
    if isinstance(obj, list):
        # Raw JSON array — treat each element as a candidate resource
        items_to_scan = [(i, item) for i, item in enumerate(obj) if isinstance(item, dict)]
    elif isinstance(obj, dict):
        if obj.get("kind") == "List":
            # kubectl List wrapper: {"kind":"List","items":[...]}
            raw_items = obj.get("items") or []
            items_to_scan = [(i, item) for i, item in enumerate(raw_items) if isinstance(item, dict)]
        else:
            items_to_scan = [(None, obj)]

    results = []
    for idx, item in items_to_scan:
        prefix = f"items[{idx}]." if idx is not None else ""
        results.extend(_extract_pki_from_k8s_resource(item, prefix=prefix))

    return results if results else None


def detect_format(data: bytes, filename: str = "") -> dict:
    result = {"type": "x509", "encoding": "pem", "was_b64": False, "was_json": False, "data": data}

    # JSON-wrapped PEM (e.g. jq output, REST API responses)
    unwrapped = _try_json_unwrap(data)
    if unwrapped is not None:
        result["was_json"] = True
        data = unwrapped
        result["data"] = data

    decoded = try_b64_decode(data)
    if decoded is not None:
        result["was_b64"] = True
        data = decoded
        result["data"] = data

    if b"-----BEGIN CERTIFICATE-----" in data:
        return {**result, "type": "x509", "encoding": "pem"}
    if b"-----BEGIN PKCS7-----" in data:
        return {**result, "type": "pkcs7", "encoding": "pem"}
    if b"-----BEGIN X509 CRL-----" in data:
        return {**result, "type": "crl", "encoding": "pem"}
    if b"-----BEGIN CERTIFICATE REQUEST-----" in data:
        return {**result, "type": "csr", "encoding": "pem"}
    if b"-----BEGIN NEW CERTIFICATE REQUEST-----" in data:
        return {**result, "type": "csr", "encoding": "pem"}

    # Private key PEM markers (check AFTER cert/csr — mixed files should parse as cert)
    for marker in _PRIVATE_KEY_MARKERS:
        if marker in data:
            return {**result, "type": "key", "encoding": "pem"}

    # Public key PEM markers (check AFTER private key — a file with both is a private key)
    for marker in _PUBLIC_KEY_MARKERS:
        if marker in data:
            return {**result, "type": "pubkey", "encoding": "pem"}

    if data and data[0:1] == b"\x30":
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            try:
                x509.load_der_x509_certificate(data)
                return {**result, "type": "x509", "encoding": "der"}
            except Exception:
                pass
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7 as p7m
            p7m.load_der_pkcs7_certificates(data)
            return {**result, "type": "pkcs7", "encoding": "der"}
        except Exception:
            pass
        try:
            x509.load_der_x509_csr(data)
            return {**result, "type": "csr", "encoding": "der"}
        except Exception:
            pass
        # Try DER CRL
        try:
            x509.load_der_x509_crl(data)
            return {**result, "type": "crl", "encoding": "der"}
        except Exception:
            pass
        # Try DER private key
        try:
            serialization.load_der_private_key(data, password=None)
            return {**result, "type": "key", "encoding": "der"}
        except Exception:
            pass
        # Try DER public key (SubjectPublicKeyInfo)
        try:
            serialization.load_der_public_key(data)
            return {**result, "type": "pubkey", "encoding": "der"}
        except Exception:
            pass
        # Try PKCS#12 (also starts with 0x30 — use OID heuristic, not load,
        # because load would fail on password-protected files)
        # PFX structure: SEQUENCE { INTEGER 3, SEQUENCE { OID 1.2.840.113549.1.7.1, ... }}
        _P12_VER3 = b"\x02\x01\x03"
        _P12_DATA_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
        if data[4:7] == _P12_VER3 and _P12_DATA_OID in data[:50]:
            return {**result, "type": "pkcs12", "encoding": "der"}

    # Java KeyStore (JKS) magic: FEEDFEED, JCEKS magic: CECECECE
    _JKS_MAGIC = b"\xfe\xed\xfe\xed"
    _JCEKS_MAGIC = b"\xce\xce\xce\xce"
    if data[:4] in (_JKS_MAGIC, _JCEKS_MAGIC):
        subtype = "jceks" if data[:4] == _JCEKS_MAGIC else "jks"
        return {**result, "type": "jks", "encoding": "der", "jks_subtype": subtype}

    fn = filename.lower()
    if fn.endswith(".der"):
        result["encoding"] = "der"
    elif fn.endswith(".pem"):
        result["encoding"] = "pem"
    for ext in (".p7s", ".p7b", ".p7c", ".p7"):
        if ext in fn:
            result["type"] = "pkcs7"
            break
    if any(x in fn for x in ("-p7.", "-p7b.", "-p7c.", "-p7s.")):
        result["type"] = "pkcs7"
    # CSR filename hints: .csr, .req, .p10 extensions
    for ext in (".csr", ".req", ".p10"):
        if ext in fn:
            result["type"] = "csr"
            break
    # CRL filename hints: .crl extension
    if fn.endswith(".crl"):
        result["type"] = "crl"
    # PKCS#12 filename hints: .p12, .pfx extensions
    for ext in (".p12", ".pfx"):
        if fn.endswith(ext):
            result["type"] = "pkcs12"
            result["encoding"] = "der"
            break
    # JKS / JCEKS filename hints
    if fn.endswith(".jks"):
        result["type"] = "jks"
        result["encoding"] = "der"
        result["jks_subtype"] = "jks"
    elif fn.endswith(".jceks"):
        result["type"] = "jks"
        result["encoding"] = "der"
        result["jks_subtype"] = "jceks"
    # Private key filename hints
    if result["type"] not in ("pkcs7", "csr"):
        for hint in ("-key.", ".key", "_key.", "-key-"):
            if hint in fn:
                result["type"] = "key"
                break
    # Public key filename hints: .pub extension
    if result["type"] not in ("pkcs7", "csr", "key"):
        for hint in ("-pub.", ".pub", "_pub.", "-pub-"):
            if hint in fn:
                result["type"] = "pubkey"
                break

    return result


def _format_load_error(label: str, exc: Exception) -> str:
    """Format a cryptography load error into readable multi-line message."""
    msg = str(exc)
    # Pattern 1: "Unable to load PEM file. See https://...url... SomeError(...)"
    m = re.match(
        r'(Unable to load (?:PEM|DER) (?:file|data)\.\s*)'
        r'See\s+(https?://\S+)\s+for more details\.\s*'
        r'(.+)',
        msg, re.DOTALL
    )
    if m:
        return (f"{label}:\n"
                f"   {m.group(1).strip()} See:\n"
                f"   {m.group(2)}\n"
                f"   {m.group(3).strip()}")

    # Pattern 2: "Could not deserialize key data. ... Details: <specific error>"
    # This is the cryptography library's generic key parse failure.
    m = re.match(
        r'(Could not deserialize key data\.)\s*'
        r'(The data may be .+?)\s*'
        r'(Details:\s*.+)',
        msg, re.DOTALL
    )
    if m:
        return (f"{label}:\n"
                f"   {m.group(1)}\n"
                f"{_wrap_error(m.group(2).strip(), indent=3, width=72)}\n"
                f"   {m.group(3).strip()}")

    # Fallback: wrap long lines at ~72 chars with 3-space indent
    if len(msg) > 72:
        return f"{label}:\n{_wrap_error(msg, indent=3, width=72)}"
    return f"{label}:\n   {msg}"


def _wrap_error(text: str, indent: int = 3, width: int = 72) -> str:
    """Word-wrap a long error message with consistent indentation."""
    prefix = " " * indent
    words = text.split()
    lines = []
    current = prefix
    for word in words:
        if len(current) + 1 + len(word) > width and current.strip():
            lines.append(current)
            current = prefix + word
        else:
            if current.strip():
                current += " " + word
            else:
                current = prefix + word
    if current.strip():
        lines.append(current)
    return "\n".join(lines)


def load_certs(data: bytes, fmt: dict) -> List[x509.Certificate]:
    ctype, enc = fmt["type"], fmt["encoding"]

    if ctype == "pkcs7":
        from cryptography.hazmat.primitives.serialization import pkcs7 as p7m
        try:
            if enc == "der":
                return p7m.load_der_pkcs7_certificates(data)
            else:
                if b"-----BEGIN PKCS7-----" not in data:
                    data = b"-----BEGIN PKCS7-----\n" + data.strip() + b"\n-----END PKCS7-----\n"
                return p7m.load_pem_pkcs7_certificates(data)
        except Exception as e:
            raise ValueError(_format_load_error("Failed to load PKCS#7", e))

    # Suppress CryptographyDeprecationWarning for certs with serial number 0
    # (e.g. Hellenic Academic RootCA 2015, included in Ubuntu ca-certificates).
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)

        certs = []
        if enc == "der":
            try:
                certs.append(x509.load_der_x509_certificate(data))
            except Exception as e:
                raise ValueError(_format_load_error("Failed to load DER certificate", e))
        else:
            blocks = re.findall(
                b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.DOTALL
            )
            if blocks:
                for b in blocks:
                    try:
                        certs.append(x509.load_pem_x509_certificate(b))
                    except Exception:
                        pass
            else:
                wrapped = b"-----BEGIN CERTIFICATE-----\n" + data.strip() + b"\n-----END CERTIFICATE-----\n"
                try:
                    certs.append(x509.load_pem_x509_certificate(wrapped))
                except Exception as e:
                    raise ValueError(_format_load_error("Failed to load PEM certificate", e))

    if not certs:
        raise ValueError("No certificates found in the input data.")
    return certs


def load_csrs(data: bytes, fmt: dict) -> List[x509.CertificateSigningRequest]:
    """Load one or more CSRs (PKCS#10) from PEM or DER data."""
    enc = fmt["encoding"]
    csrs = []

    if enc == "der":
        try:
            csrs.append(x509.load_der_x509_csr(data))
        except Exception as e:
            raise ValueError(_format_load_error("Failed to load DER CSR", e))
    else:
        # PEM: may contain multiple CSR blocks
        blocks = re.findall(
            b"-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----.*?"
            b"-----END (?:NEW )?CERTIFICATE REQUEST-----",
            data, re.DOTALL
        )
        if blocks:
            for b in blocks:
                try:
                    csrs.append(x509.load_pem_x509_csr(b))
                except Exception:
                    pass
        else:
            # Try wrapping bare base64 as PEM
            wrapped = (b"-----BEGIN CERTIFICATE REQUEST-----\n"
                       + data.strip()
                       + b"\n-----END CERTIFICATE REQUEST-----\n")
            try:
                csrs.append(x509.load_pem_x509_csr(wrapped))
            except Exception as e:
                raise ValueError(_format_load_error("Failed to load PEM CSR", e))

    if not csrs:
        raise ValueError("No CSRs found in the input data.")
    return csrs


def load_crls(data: bytes, fmt: dict) -> List[x509.CertificateRevocationList]:
    """Load one or more CRLs from PEM or DER data."""
    enc = fmt["encoding"]
    crls = []

    if enc == "der":
        try:
            crls.append(x509.load_der_x509_crl(data))
        except Exception as e:
            raise ValueError(_format_load_error("Failed to load DER CRL", e))
    else:
        # PEM: may contain multiple CRL blocks
        blocks = re.findall(
            b"-----BEGIN X509 CRL-----.*?"
            b"-----END X509 CRL-----",
            data, re.DOTALL
        )
        if blocks:
            for b in blocks:
                try:
                    crls.append(x509.load_pem_x509_crl(b))
                except Exception:
                    pass
        else:
            # Try wrapping bare base64 as PEM
            wrapped = (b"-----BEGIN X509 CRL-----\n"
                       + data.strip()
                       + b"\n-----END X509 CRL-----\n")
            try:
                crls.append(x509.load_pem_x509_crl(wrapped))
            except Exception as e:
                raise ValueError(_format_load_error("Failed to load PEM CRL", e))

    if not crls:
        raise ValueError("No CRLs found in the input data.")
    return crls


def load_keys(data: bytes, fmt: dict, password: Optional[bytes] = None) -> List[dict]:
    """Load private key(s) and return safe metadata (no private material).

    Each returned dict contains:
        key:        The private key object (for type detection only)
        pub:        The corresponding public key object
        pem_format: str like "PKCS#8", "PKCS#1 (RSA)", etc.
        encrypted:  bool — whether the PEM was encrypted (and no password given)
    """
    enc = fmt["encoding"]
    results = []

    if enc == "der":
        try:
            key = serialization.load_der_private_key(data, password=password)
        except TypeError:
            if password is None:
                raise ValueError("Encrypted DER private key — password required.\n"
                                 "   Hint: use PW=<password> to supply the passphrase.")
            raise
        except ValueError as e:
            if password is not None and "Incorrect password" in str(e):
                raise ValueError("Incorrect password for DER private key.")
            # Try OID fallback before giving up
            oid = _extract_pkcs8_oid(data)
            if oid:
                oid_name = _pubkey_oid_name(oid)
                pqc = _PQC_KEY_INFO.get(oid)
                results.append({
                    "key": None, "pub": None,
                    "pem_format": "DER", "encrypted": False,
                    "oid": oid, "oid_name": oid_name, "pqc_info": pqc,
                })
                return results
            raise ValueError(_format_load_error("Failed to load DER private key", e))
        except Exception as e:
            # Try OID fallback before giving up
            oid = _extract_pkcs8_oid(data)
            if oid:
                oid_name = _pubkey_oid_name(oid)
                pqc = _PQC_KEY_INFO.get(oid)
                results.append({
                    "key": None, "pub": None,
                    "pem_format": "DER", "encrypted": False,
                    "oid": oid, "oid_name": oid_name, "pqc_info": pqc,
                })
                return results
            raise ValueError(_format_load_error("Failed to load DER private key", e))
        results.append({
            "key": key, "pub": key.public_key(),
            "pem_format": "DER", "encrypted": False,
            "oid": None, "oid_name": None, "pqc_info": None,
        })
        return results

    # PEM: detect each key block
    # Combine all private key PEM patterns
    pattern = (
        rb"-----BEGIN ((?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----"
        rb"(.*?)"
        rb"-----END \1-----"
    )
    blocks = re.findall(pattern, data, re.DOTALL)

    if not blocks:
        raise ValueError("No private keys found in the input data.")

    for label_bytes, body in blocks:
        marker = b"-----BEGIN " + label_bytes + b"-----"
        pem_format, is_encrypted = _PRIVATE_KEY_MARKERS.get(
            marker, ("Unknown", False)
        )

        # Check for traditional PEM encryption (Proc-Type header)
        if b"Proc-Type:" in body and b"ENCRYPTED" in body:
            is_encrypted = True
            pem_format = pem_format.rstrip(")") + ", encrypted)" if "(" in pem_format else pem_format + " (encrypted)"

        full_pem = b"-----BEGIN " + label_bytes + b"-----" + body + b"-----END " + label_bytes + b"-----\n"

        if is_encrypted:
            if password is not None:
                # Try to decrypt with the supplied password
                try:
                    key = serialization.load_pem_private_key(full_pem, password=password)
                    results.append({
                        "key": key, "pub": key.public_key(),
                        "pem_format": pem_format.replace(" (encrypted)", "").replace(", encrypted)", ")"),
                        "encrypted": False,
                        "oid": None, "oid_name": None, "pqc_info": None,
                    })
                    continue
                except ValueError as e:
                    if "Incorrect password" in str(e) or "Could not deserialize" in str(e):
                        raise ValueError(f"Incorrect password for encrypted private key.")
                    raise ValueError(_format_load_error("Failed to decrypt private key", e))
                except Exception as e:
                    raise ValueError(_format_load_error("Failed to decrypt private key", e))
            else:
                # No password — show encrypted status (graceful degradation)
                results.append({
                    "key": None, "pub": None,
                    "pem_format": pem_format, "encrypted": True,
                    "oid": None, "oid_name": None, "pqc_info": None,
                })
                continue

        if label_bytes == b"OPENSSH PRIVATE KEY":
            # OpenSSH format — try loading, but it may not be supported for all key types
            try:
                key = serialization.load_ssh_private_key(full_pem, password=password)
                results.append({
                    "key": key, "pub": key.public_key(),
                    "pem_format": pem_format, "encrypted": False,
                    "oid": None, "oid_name": None, "pqc_info": None,
                })
            except Exception as e:
                results.append({
                    "key": None, "pub": None,
                    "pem_format": pem_format + " (unsupported)", "encrypted": False,
                    "oid": None, "oid_name": None, "pqc_info": None,
                })
            continue

        try:
            key = serialization.load_pem_private_key(full_pem, password=password)
        except TypeError:
            # Password was not given but key is encrypted (shouldn't get here
            # because is_encrypted check above should have caught it, but handle it)
            results.append({
                "key": None, "pub": None,
                "pem_format": pem_format + " (encrypted)", "encrypted": True,
                "oid": None, "oid_name": None, "pqc_info": None,
            })
            continue
        except Exception as e:
            # OID fallback: try to extract algorithm info from the raw DER
            # Only works for PKCS#8 (BEGIN PRIVATE KEY) — not legacy formats
            if label_bytes == b"PRIVATE KEY":
                try:
                    import base64 as b64m
                    lines = full_pem.split(b"\n")
                    b64_lines = [l for l in lines if not l.startswith(b"-----") and l.strip()]
                    der_data = b64m.b64decode(b"".join(b64_lines))
                    oid = _extract_pkcs8_oid(der_data)
                    if oid:
                        oid_name = _pubkey_oid_name(oid)
                        pqc = _PQC_KEY_INFO.get(oid)
                        results.append({
                            "key": None, "pub": None,
                            "pem_format": pem_format, "encrypted": False,
                            "oid": oid, "oid_name": oid_name, "pqc_info": pqc,
                        })
                        continue
                except Exception:
                    pass
            raise ValueError(_format_load_error("Failed to load PEM private key", e))

        results.append({
            "key": key, "pub": key.public_key(),
            "pem_format": pem_format, "encrypted": False,
            "oid": None, "oid_name": None, "pqc_info": None,
        })

    if not results:
        raise ValueError("No private keys found in the input data.")
    return results


def load_public_keys(data: bytes, fmt: dict) -> List[dict]:
    """Load public key(s) and return metadata.

    Each returned dict contains:
        pub:        The public key object (or None if unsupported algorithm)
        pem_format: str like "SubjectPublicKeyInfo (PKCS#8)", "PKCS#1 (RSA)", etc.
        oid:        Algorithm OID dotted string (if available)
        oid_name:   Human-readable algorithm name from OID lookup
        pqc_info:   Tuple from _PQC_KEY_INFO or None
        key_der:    Raw DER bytes of SubjectPublicKeyInfo (for fingerprinting)
    """
    enc = fmt["encoding"]
    results = []

    if enc == "der":
        pub, oid, key_der = _try_load_public_key(data, is_der=True)
        oid_name = _pubkey_oid_name(oid)
        pqc = _PQC_KEY_INFO.get(oid) if oid else None
        results.append({
            "pub": pub, "pem_format": "DER (SubjectPublicKeyInfo)",
            "oid": oid, "oid_name": oid_name, "pqc_info": pqc,
            "key_der": key_der,
        })
        return results

    # PEM: detect each public key block
    pattern = (
        rb"-----BEGIN ((?:RSA )?PUBLIC KEY)-----"
        rb"(.*?)"
        rb"-----END \1-----"
    )
    blocks = re.findall(pattern, data, re.DOTALL)

    if not blocks:
        raise ValueError("No public keys found in the input data.")

    for label_bytes, body in blocks:
        marker = b"-----BEGIN " + label_bytes + b"-----"
        pem_format = _PUBLIC_KEY_MARKERS.get(marker, "Unknown")

        full_pem = (b"-----BEGIN " + label_bytes + b"-----"
                    + body
                    + b"-----END " + label_bytes + b"-----\n")

        pub, oid, key_der = _try_load_public_key(full_pem, is_der=False)
        oid_name = _pubkey_oid_name(oid)
        pqc = _PQC_KEY_INFO.get(oid) if oid else None

        results.append({
            "pub": pub, "pem_format": pem_format,
            "oid": oid, "oid_name": oid_name, "pqc_info": pqc,
            "key_der": key_der,
        })

    if not results:
        raise ValueError("No public keys found in the input data.")
    return results


# -- Public key OID helpers --

# Standard public key algorithm OIDs (not signatures — these identify key types)
_PUBKEY_ALGO_NAMES = {
    "1.2.840.113549.1.1.1":    "rsaEncryption",
    "1.2.840.10045.2.1":       "id-ecPublicKey",
    "1.2.840.10040.4.1":       "id-dsa",
    "1.3.101.110":             "X25519",
    "1.3.101.111":             "X448",
    "1.3.101.112":             "Ed25519",
    "1.3.101.113":             "Ed448",
}


def _pubkey_oid_name(oid: Optional[str]) -> Optional[str]:
    """Look up a public key algorithm OID in all known tables."""
    if oid is None:
        return None
    # PQC table first (has the most detail)
    pqc = _PQC_KEY_INFO.get(oid)
    if pqc:
        return pqc[0]
    # Standard pubkey OIDs
    name = _PUBKEY_ALGO_NAMES.get(oid)
    if name:
        return name
    # Signature OIDs (sometimes used in SPKI too)
    name = _SIG_ALGO_NAMES.get(oid)
    if name:
        return name
    return f"Unknown ({oid})"


# Reverse mapping: key class -> algorithm OID
_KEY_TYPE_OIDS = {
    rsa.RSAPrivateKey:               "1.2.840.113549.1.1.1",
    rsa.RSAPublicKey:                "1.2.840.113549.1.1.1",
    ec.EllipticCurvePrivateKey:      "1.2.840.10045.2.1",
    ec.EllipticCurvePublicKey:       "1.2.840.10045.2.1",
    dsa.DSAPrivateKey:               "1.2.840.10040.4.1",
    dsa.DSAPublicKey:                "1.2.840.10040.4.1",
    ed25519.Ed25519PrivateKey:       "1.3.101.112",
    ed25519.Ed25519PublicKey:        "1.3.101.112",
    ed448.Ed448PrivateKey:           "1.3.101.113",
    ed448.Ed448PublicKey:            "1.3.101.113",
    x25519.X25519PrivateKey:         "1.3.101.110",
    x25519.X25519PublicKey:          "1.3.101.110",
    x448.X448PrivateKey:             "1.3.101.111",
    x448.X448PublicKey:              "1.3.101.111",
}


def _key_algo_oid(key) -> Optional[str]:
    """Derive the algorithm OID from a loaded key object."""
    if key is None:
        return None
    for cls, oid in _KEY_TYPE_OIDS.items():
        if isinstance(key, cls):
            return oid
    return None


def _try_load_public_key(data: bytes, is_der: bool) -> tuple:
    """Try to load a public key; on failure, extract OID from raw SPKI.

    Returns: (pub_key_object_or_None, oid_string_or_None, der_bytes_or_None)
    """
    loader = serialization.load_der_public_key if is_der else serialization.load_pem_public_key
    try:
        pub = loader(data)
        # Get DER for fingerprinting
        key_der = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        oid = _extract_spki_oid(key_der)
        return (pub, oid, key_der)
    except Exception:
        pass

    # Fallback: parse the SPKI structure to get the OID even though
    # we can't instantiate the key object
    der_data = data
    if not is_der:
        # Strip PEM armour to get raw DER
        try:
            import base64 as b64m
            lines = data.split(b"\n")
            b64_lines = [l for l in lines if not l.startswith(b"-----") and l.strip()]
            der_data = b64m.b64decode(b"".join(b64_lines))
        except Exception:
            return (None, None, None)

    oid = _extract_spki_oid(der_data)
    return (None, oid, der_data)


def _extract_spki_oid(der: bytes) -> Optional[str]:
    """Extract the algorithm OID from a DER-encoded SubjectPublicKeyInfo.

    SubjectPublicKeyInfo ::= SEQUENCE {
        algorithm  AlgorithmIdentifier ::= SEQUENCE {
            algorithm  OBJECT IDENTIFIER,
            parameters ANY OPTIONAL },
        subjectPublicKey BIT STRING }

    We parse just enough DER to reach the OID.
    """
    try:
        pos = 0
        # Outer SEQUENCE
        if der[pos] != 0x30:
            return None
        pos, _ = _der_read_length(der, pos + 1)

        # Inner SEQUENCE (AlgorithmIdentifier)
        if der[pos] != 0x30:
            return None
        pos, _ = _der_read_length(der, pos + 1)

        # OID tag
        if der[pos] != 0x06:
            return None
        pos += 1
        oid_len = der[pos]
        pos += 1
        oid_bytes = der[pos:pos + oid_len]
        return _decode_oid(oid_bytes)
    except (IndexError, ValueError):
        return None


def _extract_pkcs8_oid(der: bytes) -> Optional[str]:
    """Extract the algorithm OID from a DER-encoded PKCS#8 PrivateKeyInfo.

    PrivateKeyInfo ::= SEQUENCE {
        version    INTEGER,
        algorithm  AlgorithmIdentifier ::= SEQUENCE {
            algorithm  OBJECT IDENTIFIER,
            parameters ANY OPTIONAL },
        privateKey OCTET STRING }

    Same as SPKI but with an INTEGER (version) before the AlgorithmIdentifier.
    """
    try:
        pos = 0
        # Outer SEQUENCE
        if der[pos] != 0x30:
            return None
        pos, _ = _der_read_length(der, pos + 1)

        # INTEGER (version) — skip it
        if der[pos] != 0x02:
            return None
        pos += 1
        int_len = der[pos]
        pos += 1 + int_len  # skip past the integer value

        # Inner SEQUENCE (AlgorithmIdentifier)
        if der[pos] != 0x30:
            return None
        pos, _ = _der_read_length(der, pos + 1)

        # OID tag
        if der[pos] != 0x06:
            return None
        pos += 1
        oid_len = der[pos]
        pos += 1
        oid_bytes = der[pos:pos + oid_len]
        return _decode_oid(oid_bytes)
    except (IndexError, ValueError):
        return None


def _der_read_length(der: bytes, pos: int) -> tuple:
    """Read a DER length field. Returns (new_pos, length)."""
    b = der[pos]
    if b < 0x80:
        return (pos + 1, b)
    num_bytes = b & 0x7F
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | der[pos + 1 + i]
    return (pos + 1 + num_bytes, length)


def _decode_oid(data: bytes) -> str:
    """Decode a DER-encoded OID value to dotted string."""
    if not data:
        return ""
    components = []
    # First byte encodes two components: X.Y where byte = 40*X + Y
    components.append(str(data[0] // 40))
    components.append(str(data[0] % 40))

    value = 0
    for b in data[1:]:
        if b & 0x80:
            value = (value << 7) | (b & 0x7F)
        else:
            value = (value << 7) | b
            components.append(str(value))
            value = 0
    return ".".join(components)


def load_pkcs12(data: bytes, fmt: dict, password: Optional[bytes] = None) -> dict:
    """Load a PKCS#12 (.p12/.pfx) container and return its components.

    Returns a dict:
        key:            key info dict (as from load_keys) or None
        cert:           x509.Certificate or None (the "main" certificate)
        chain:          list of x509.Certificate (additional CA certs)
        encrypted:      bool — True if the container is password-protected
                        and no (correct) password was supplied
    """
    # Try with supplied password first, then fallback strategies
    passwords_to_try = []
    if password is not None:
        passwords_to_try.append(password)
    passwords_to_try.append(None)     # no password
    passwords_to_try.append(b"")      # empty password (some tools differ)

    last_exc = None
    for pw in passwords_to_try:
        try:
            key, cert, chain = p12m.load_key_and_certificates(data, password=pw)
            if chain is None:
                chain = []

            # Build key info dict (reuse the KeyFormatter-compatible structure)
            key_info = None
            if key is not None:
                try:
                    pub = key.public_key()
                except Exception:
                    pub = None
                key_info = {
                    "key": key, "pub": pub,
                    "pem_format": "PKCS#12", "encrypted": False,
                    "oid": None, "oid_name": None, "pqc_info": None,
                }

            if key is None and cert is None and not chain:
                raise ValueError("PKCS#12 container is empty (no key, no certificates).")

            return {"key": key_info, "cert": cert, "chain": chain, "encrypted": False}
        except Exception as e:
            last_exc = e
            continue

    # All attempts failed
    if password is not None:
        # A specific password was provided but it didn't work
        raise ValueError("Incorrect password for PKCS#12 container.")

    # No password was provided — graceful degradation
    return {"key": None, "cert": None, "chain": [], "encrypted": True}


# ---------------------------------------------------------------------------
#  JKS / JCEKS loader
# ---------------------------------------------------------------------------

def load_jks(data: bytes, fmt: dict, password: Optional[bytes] = None) -> dict:
    """Load a Java KeyStore (.jks) or JCEKS (.jceks) container.

    Returns dict with:
        entries: list of dicts, each with:
            type:  "trusted_cert" | "private_key" | "secret_key"
            alias: str
            cert:  x509.Certificate (for trusted_cert and private_key)
            chain: list of x509.Certificate (for private_key, includes leaf)
            key_info: dict (for private_key, KeyFormatter-compatible)
            secret:   dict with algorithm/key_size (for secret_key)
        encrypted: bool (True if password-protected and could not open)
        store_type: "jks" | "jceks"
    """
    try:
        import jks
    except ImportError:
        raise ValueError(
            "JKS/JCEKS support requires the 'pyjks' library.\n"
            "   Install:  pip install pyjks"
        )

    pw_str = None
    if password is not None:
        pw_str = password.decode("utf-8", errors="replace")

    # Try passwords: supplied → "changeit" (Java default) → empty
    pw_candidates = []
    if pw_str is not None:
        pw_candidates.append(pw_str)
    pw_candidates.extend(["changeit", ""])

    ks = None
    for pw in pw_candidates:
        try:
            ks = jks.KeyStore.loads(data, pw, try_decrypt_keys=False)
            break
        except jks.KeystoreSignatureException:
            continue
        except Exception:
            continue

    if ks is None:
        if password is not None:
            raise ValueError("Incorrect password for Java KeyStore.")
        return {"entries": [], "encrypted": True,
                "store_type": fmt.get("jks_subtype", "jks"),
                "password_used": None}

    store_pw = pw  # password that opened the store
    entries = []

    for alias in sorted(ks.entries.keys()):
        entry = ks.entries[alias]

        if isinstance(entry, jks.TrustedCertEntry):
            cert = _jks_load_cert(entry.cert, alias)
            if cert:
                entries.append({
                    "type": "trusted_cert", "alias": alias,
                    "cert": cert, "chain": [], "key_info": None, "secret": None,
                })

        elif isinstance(entry, jks.PrivateKeyEntry):
            # Load certificate chain
            chain_certs = []
            for cert_type, cert_data in entry.cert_chain:
                c = _jks_load_cert(cert_data, alias)
                if c:
                    chain_certs.append(c)

            # Decrypt private key (workaround for pyjks/pyasn1 bug)
            key_info = _jks_decrypt_private_key(entry, store_pw)

            entries.append({
                "type": "private_key", "alias": alias,
                "cert": chain_certs[0] if chain_certs else None,
                "chain": chain_certs,
                "key_info": key_info,
                "secret": None,
            })

        elif isinstance(entry, jks.SecretKeyEntry):
            # Decrypt secret key
            secret = None
            try:
                if not entry.is_decrypted():
                    entry.decrypt(store_pw)
                secret = {
                    "algorithm": getattr(entry, "algorithm", "Unknown"),
                    "key_size": len(entry.key) * 8 if entry.key else 0,
                }
            except Exception:
                secret = {"algorithm": "Unknown (encrypted)", "key_size": 0}

            entries.append({
                "type": "secret_key", "alias": alias,
                "cert": None, "chain": [], "key_info": None,
                "secret": secret,
            })

    return {"entries": entries, "encrypted": False,
            "store_type": fmt.get("jks_subtype", "jks"),
            "password_used": store_pw}


# --- JKS helper: load a single DER certificate ---
def _jks_load_cert(cert_data, alias):
    """Load a DER-encoded X.509 certificate from a JKS entry."""
    if isinstance(cert_data, str):
        cert_data = cert_data.encode("latin-1")
    try:
        return x509.load_der_x509_certificate(cert_data)
    except Exception:
        return None


# --- JKS helper: decrypt private key (pyasn1 workaround) ---
def _jks_decrypt_private_key(entry, password_str):
    """Decrypt a JKS/JCEKS private key entry, working around pyjks/pyasn1 bug."""
    try:
        from pyasn1.codec.der.decoder import decode as der_decode
        from jks import sun_crypto

        raw = entry._encrypted
        seq, _ = der_decode(raw)
        algo_seq = seq.getComponentByPosition(0)
        algo_oid = tuple(algo_seq.getComponentByPosition(0))
        encrypted_data = bytes(seq.getComponentByPosition(1))

        if algo_oid == sun_crypto.SUN_JKS_ALGO_ID:
            plaintext = sun_crypto.jks_pkey_decrypt(encrypted_data, password_str)
        elif algo_oid == sun_crypto.SUN_JCE_ALGO_ID:
            pbe_params = algo_seq.getComponentByPosition(1)
            salt = pbe_params.getComponentByPosition(0).asOctets()
            iteration_count = int(pbe_params.getComponentByPosition(1))
            plaintext = sun_crypto.jce_pbe_decrypt(
                encrypted_data, password_str, salt, iteration_count)
        else:
            return None

        key = serialization.load_der_private_key(plaintext, password=None)
        try:
            pub = key.public_key()
        except Exception:
            pub = None
        return {
            "key": key, "pub": pub,
            "pem_format": "JKS", "encrypted": False,
            "oid": None, "oid_name": None, "pqc_info": None,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
#  ASN.1 mini-decoder for PQC/Hybrid extensions
# ---------------------------------------------------------------------------

def _decode_oid_from_bytes(data: bytes, offset: int = 0) -> Tuple[str, int]:
    """Decode a DER-encoded OID starting at offset. Returns (dotted_string, end_offset)."""
    if offset >= len(data) or data[offset] != 0x06:
        return ("", offset)
    length = data[offset + 1]
    oid_bytes = data[offset + 2: offset + 2 + length]
    # Decode OID
    components = []
    first = oid_bytes[0]
    components.append(str(first // 40))
    components.append(str(first % 40))
    value = 0
    for b in oid_bytes[1:]:
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            components.append(str(value))
            value = 0
    return (".".join(components), offset + 2 + length)


def _decode_algorithm_identifier(data: bytes) -> str:
    """Decode an ASN.1 AlgorithmIdentifier SEQUENCE and return the algorithm name."""
    try:
        if not data or data[0] != 0x30:
            return f"(unparseable, {len(data)} bytes)"
        # Skip SEQUENCE tag + length
        offset = 2
        if data[1] & 0x80:
            len_bytes = data[1] & 0x7F
            offset = 2 + len_bytes
        oid_str, _ = _decode_oid_from_bytes(data, offset)
        # Look up all our OID tables
        name = _SIG_ALGO_NAMES.get(oid_str) or _PQC_KEY_INFO.get(oid_str, (None,))[0]
        return name or oid_str
    except Exception:
        return f"(decode error, {len(data)} bytes)"


def _decode_spki_algorithm(data: bytes) -> Optional[str]:
    """Try to extract the algorithm OID from a SubjectPublicKeyInfo structure."""
    try:
        if not data or data[0] != 0x30:
            return None
        # SPKI = SEQUENCE { AlgorithmIdentifier, BIT STRING }
        # Skip outer SEQUENCE tag+len, then find inner SEQUENCE (AlgId)
        offset = 2
        if data[1] & 0x80:
            len_bytes = data[1] & 0x7F
            offset = 2 + len_bytes
        return _decode_algorithm_identifier(data[offset:]) if data[offset] == 0x30 else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
#  Extension Helpers
# ---------------------------------------------------------------------------

_EXT_NAME_MAP = {
    ExtensionOID.KEY_USAGE:                      "X509v3 Key Usage",
    ExtensionOID.EXTENDED_KEY_USAGE:             "X509v3 Extended Key Usage",
    ExtensionOID.BASIC_CONSTRAINTS:              "X509v3 Basic Constraints",
    ExtensionOID.SUBJECT_KEY_IDENTIFIER:         "X509v3 Subject Key Identifier",
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER:       "X509v3 Authority Key Identifier",
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME:       "X509v3 Subject Alternative Name",
    ExtensionOID.ISSUER_ALTERNATIVE_NAME:        "X509v3 Issuer Alternative Name",
    ExtensionOID.CRL_DISTRIBUTION_POINTS:        "X509v3 CRL Distribution Points",
    ExtensionOID.CERTIFICATE_POLICIES:           "X509v3 Certificate Policies",
    ExtensionOID.AUTHORITY_INFORMATION_ACCESS:   "Authority Information Access",
    ExtensionOID.OCSP_NO_CHECK:                  "OCSP No Check",
    ExtensionOID.INHIBIT_ANY_POLICY:             "X509v3 Inhibit Any Policy",
    ExtensionOID.NAME_CONSTRAINTS:               "X509v3 Name Constraints",
}

# Add hybrid extension OIDs by dotted-string (not in ExtensionOID enum yet)
_EXT_NAME_BY_OID = {
    "2.5.29.72": "X509v3 Subject Alternative Public Key Info",
    "2.5.29.73": "X509v3 Alternative Signature Algorithm",
    "2.5.29.74": "X509v3 Alternative Signature Value",
}


def ext_name(ext) -> str:
    for k, v in _EXT_NAME_MAP.items():
        if ext.oid == k:
            return v
    # Check OID-based map (hybrid extensions, etc.)
    if ext.oid.dotted_string in _EXT_NAME_BY_OID:
        return _EXT_NAME_BY_OID[ext.oid.dotted_string]
    n = ext.oid._name
    return n if n and n != "Unknown OID" else f"OID {ext.oid.dotted_string}"


def key_usage_list(ku: x509.KeyUsage) -> List[str]:
    usages = []
    for attr, label in [
        ("digital_signature",  "Digital Signature"),
        ("content_commitment", "Content Commitment"),
        ("key_encipherment",   "Key Encipherment"),
        ("data_encipherment",  "Data Encipherment"),
        ("key_agreement",      "Key Agreement"),
        ("key_cert_sign",      "Certificate Sign"),
        ("crl_sign",           "CRL Sign"),
    ]:
        try:
            if getattr(ku, attr):
                usages.append(label)
        except ValueError:
            pass
    try:
        if ku.key_agreement:
            try:
                if ku.encipher_only: usages.append("Encipher Only")
            except ValueError: pass
            try:
                if ku.decipher_only: usages.append("Decipher Only")
            except ValueError: pass
    except ValueError:
        pass
    return usages


def san_list(san) -> List[str]:
    names = []
    for gn in san:
        if isinstance(gn, x509.DNSName):            names.append(f"DNS:{gn.value}")
        elif isinstance(gn, x509.IPAddress):        names.append(f"IP Address:{gn.value}")
        elif isinstance(gn, x509.RFC822Name):       names.append(f"email:{gn.value}")
        elif isinstance(gn, x509.UniformResourceIdentifier): names.append(f"URI:{gn.value}")
        elif isinstance(gn, x509.DirectoryName):    names.append(f"DirName:{format_dn_oneline(gn.value)}")
        else:                                       names.append(str(gn))
    return names


def ext_detail(ext) -> List[str]:
    val = ext.value
    lines = []

    if isinstance(val, x509.KeyUsage):
        lines = sorted(key_usage_list(val), key=str.lower)

    elif isinstance(val, x509.ExtendedKeyUsage):
        for u in sorted(val, key=lambda u: u.dotted_string):
            lines.append(_EKU_NAMES.get(u.dotted_string, u._name or u.dotted_string))

    elif isinstance(val, x509.BasicConstraints):
        lines.append(f"CA:{'TRUE' if val.ca else 'FALSE'}")
        if val.path_length is not None:
            lines.append(f"pathlen:{val.path_length}")

    elif isinstance(val, x509.SubjectKeyIdentifier):
        lines.append(format_fp(val.digest))

    elif isinstance(val, x509.AuthorityKeyIdentifier):
        if val.key_identifier:
            lines.append(format_fp(val.key_identifier))

    elif isinstance(val, (x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
        lines = sorted(san_list(val), key=str.lower)

    elif isinstance(val, x509.CRLDistributionPoints):
        for dp in val:
            if dp.full_name:
                lines.append("Full Name:")
                for n in dp.full_name:
                    lines.append(f"  URI:{n.value}")

    elif isinstance(val, x509.CertificatePolicies):
        for pol in val:
            lines.append(f"Policy: {pol.policy_identifier.dotted_string}")
            if pol.policy_qualifiers:
                for pq in pol.policy_qualifiers:
                    if isinstance(pq, str):
                        lines.append(f"  CPS: {pq}")
                    elif hasattr(pq, 'explicit_text') and pq.explicit_text:
                        lines.append(f"  Explicit Text: {pq.explicit_text}")

    elif isinstance(val, x509.AuthorityInformationAccess):
        for desc in val:
            method = "OCSP" if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP else "CA Issuers"
            lines.append(f"{method} - URI:{desc.access_location.value}")

    elif isinstance(val, x509.UnrecognizedExtension):
        oid_str = ext.oid.dotted_string
        raw = val.value
        # Hybrid cert extensions
        if oid_str == "2.5.29.73":  # altSignatureAlgorithm
            algo_name = _decode_algorithm_identifier(raw)
            lines.append(algo_name)
        elif oid_str == "2.5.29.74":  # altSignatureValue
            lines.append(f"({len(raw)} bytes)")
            # Show first line of hex like OpenSSL
            pairs = [f"{b:02x}" for b in raw[:18]]
            if pairs:
                preview = ":".join(pairs)
                if len(raw) > 18: preview += ":..."
                lines.append(f"  {preview}")
        elif oid_str == "2.5.29.72":  # subjectAltPublicKeyInfo
            algo_name = _decode_spki_algorithm(raw)
            if algo_name:
                lines.append(f"Algorithm: {algo_name}")
            lines.append(f"({len(raw)} bytes)")
        else:
            if len(raw) < 100:
                lines.append(raw.hex())
            else:
                lines.append(f"({len(raw)} bytes)")

    else:
        try:
            s = str(val)
            if len(s) < 200:
                lines.append(s)
        except Exception:
            pass

    return lines


def ext_detail_full(ext) -> List[str]:
    """Extension detail in OpenSSL's native comma-separated format (for summary_3/4)."""
    val = ext.value

    if isinstance(val, x509.KeyUsage):
        usages = key_usage_list(val)
        return [", ".join(usages)] if usages else []

    elif isinstance(val, x509.ExtendedKeyUsage):
        names = [_EKU_NAMES.get(u.dotted_string, u._name or u.dotted_string) for u in val]
        return [", ".join(names)] if names else []

    elif isinstance(val, (x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
        names = san_list(val)
        return [", ".join(names)] if names else []

    return ext_detail(ext)


# ---------------------------------------------------------------------------
#  Cert Formatter
# ---------------------------------------------------------------------------

class CertFormatter:
    def __init__(self, verbose=0, show_pub=False, show_fp=False):
        self.verbose = verbose
        self.show_pub = show_pub
        self.show_fp = show_fp

    def format(self, cert, idx: int, level: str) -> str:
        method = getattr(self, f"_{level}", self._summary_1)
        return method(cert, idx)

    def _summary_0(self, cert, idx: int) -> str:
        o = [f"{idx}: Certificate:"]
        o.append(f"  {'Issuer:':<15}  {dn_label(cert.issuer)}")
        o.append(f"  {'Subject:':<15}  {dn_label(cert.subject)}")
        o.append(f"  {'Serial Number:':<15}    {format_serial(_get_serial(cert))}")
        o.append(f"  {'Not Before:':<15}    {format_dt(_not_before(cert))}")
        o.append(f"  {'Not After:':<15}    {format_dt(_not_after(cert))}")
        if self.show_fp:
            o.append(""); o.extend(self._fps(cert))
        if self.show_pub:
            o.extend(self._pub(cert))
        return "\n".join(o)

    def _summary_1(self, cert, idx: int) -> str:
        o = [f"{idx}: Certificate:"]
        o.append(f"  Signature Algorithm: {sig_algo_name(cert)}")
        o.append(f"  - Public Key Algorithm: {pub_key_algo(cert)}")
        bits = pub_key_bits(cert)
        if bits: o.append(f"  - Public-Key: ({bits} bit)")
        o.extend(self._dn_block("Issuer:", cert.issuer))
        o.extend(self._dn_block("Subject:", cert.subject))
        o.append("  Validity:")
        o.append(f"     Not Before: {format_dt(_not_before(cert))}")
        o.append(f"     Not After : {format_dt(_not_after(cert))}")
        o.append("  Data:")
        o.append(f"     Version: {cert.version.value + 1} (0x{cert.version.value})")
        o.append(f"     Serial Number: {format_serial(_get_serial(cert))}")
        ext_lines = self._exts_summary(cert)
        if ext_lines:
            o.append("")
            o.append("  X509v3 extensions:")
            o.extend(ext_lines)
        if self.show_fp:
            o.append(""); o.extend(self._fps(cert))
        if self.show_pub:
            o.extend(self._pub(cert))
        return "\n".join(o)

    def _summary_2(self, cert, idx: int) -> str:
        o = [f"{idx}: Certificate:"]
        o.append(f"  Signature Algorithm: {sig_algo_name(cert)}")
        o.append(f"  - Public Key Algorithm: {pub_key_algo(cert)}")
        bits = pub_key_bits(cert)
        if bits: o.append(f"  - Public-Key: ({bits} bit)")
        o.extend(self._dn_block("Issuer:", cert.issuer))
        o.extend(self._dn_block("Subject:", cert.subject))
        o.append("  Validity:")
        o.append(f"     Not Before: {format_dt(_not_before(cert))}")
        o.append(f"     Not After : {format_dt(_not_after(cert))}")
        o.append("  Data:")
        o.append(f"     Version: {cert.version.value + 1} (0x{cert.version.value})")
        o.append(f"     Serial Number: {format_serial(_get_serial(cert))}")
        ext_lines = self._exts_verbose(cert)
        if ext_lines:
            o.append("")
            o.append("  X509v3 extensions:")
            o.extend(ext_lines)
        o.append(""); o.extend(self._fps(cert))
        if self.show_pub:
            o.extend(self._pub(cert))
        return "\n".join(o)

    def _summary_3(self, cert, idx: int) -> str:
        o = [f"{idx}: Certificate:"]
        text = self._full_text(cert)
        skip_hex = False
        hex_shown = False
        for line in text.split("\n"):
            stripped = line.strip()
            if re.match(r'^\s*(Modulus:|Signature Value:|pub:)\s*$', line):
                skip_hex = True
                hex_shown = False
                o.append(line)
                continue
            if skip_hex and re.match(r'^[a-f0-9:]+\s*$', stripped) and len(stripped) >= 2:
                if not hex_shown:
                    m = re.match(r'^(\s*)', line)
                    o.append(f"{m.group(1) if m else '    '}...hex...")
                    hex_shown = True
                continue
            if skip_hex and not re.match(r'^[a-f0-9:]+\s*$', stripped):
                skip_hex = False
                hex_shown = False
            o.append(line)
        o.append(""); o.extend(self._fps(cert))
        if self.show_pub:
            o.extend(self._pub(cert))
        return "\n".join(o)

    def _summary_4(self, cert, idx: int) -> str:
        o = [f"{idx}: Certificate:"]
        o.append(self._full_text(cert))
        if self.show_fp:
            o.append(""); o.extend(self._fps(cert))
        if self.show_pub:
            o.extend(self._pub(cert))
        return "\n".join(o)

    def _dn_block(self, label: str, name: x509.Name) -> List[str]:
        o = []
        comps = parse_dn(name)
        o.append(f"  {label:<8}")
        if "CN" in comps:
            o.append(f"           CN = {comps['CN']}")
        for tag in sorted(comps):
            if tag == "CN": continue
            o.append(f"           {tag:<2} = {comps[tag]}")
        return o

    def _exts_summary(self, cert) -> List[str]:
        o = []
        try:
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            crit = " critical" if ku.critical else ""
            o.append(f"     X509v3 Key Usage:{crit}")
            for u in sorted(key_usage_list(ku.value), key=str.lower):
                o.append(f"        {u}")
        except x509.ExtensionNotFound: pass

        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            crit = " critical" if eku.critical else ""
            o.append(f"     X509v3 Extended Key Usage:{crit}")
            for u in sorted(eku.value, key=lambda u: u.dotted_string):
                o.append(f"        {_EKU_NAMES.get(u.dotted_string, u._name or u.dotted_string)}")
        except x509.ExtensionNotFound: pass

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            crit = " critical" if san_ext.critical else ""
            o.append(f"     X509v3 Subject Alternative Name:{crit}")
            for n in sorted(san_list(san_ext.value), key=str.lower):
                o.append(f"        {n}")
        except x509.ExtensionNotFound: pass

        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if bc.value.ca:
                crit = " critical" if bc.critical else ""
                o.append(f"     X509v3 Basic Constraints:{crit}")
                o.append(f"        CA:TRUE")
                if bc.value.path_length is not None:
                    o.append(f"        pathlen:{bc.value.path_length}")
        except x509.ExtensionNotFound: pass

        # Hybrid certificate extensions (PQC)
        hybrid_separator_shown = False
        for ext in cert.extensions:
            oid = ext.oid.dotted_string
            if oid == "2.5.29.72":  # subjectAltPublicKeyInfo
                if not hybrid_separator_shown:
                    o.append(f"     ------")
                    hybrid_separator_shown = True
                raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else b""
                algo = _decode_spki_algorithm(raw)
                o.append(f"     X509v3 Subject Alternative Public Key Info:")
                o.append(f"        {algo or 'present'} ({len(raw)} bytes)")
            elif oid == "2.5.29.73":  # altSignatureAlgorithm
                if not hybrid_separator_shown:
                    o.append(f"     ------")
                    hybrid_separator_shown = True
                raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else b""
                algo = _decode_algorithm_identifier(raw)
                o.append(f"     X509v3 Alternative Signature Algorithm:")
                o.append(f"        {algo}")
            elif oid == "2.5.29.74":  # altSignatureValue
                if not hybrid_separator_shown:
                    o.append(f"     ------")
                    hybrid_separator_shown = True
                raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else b""
                o.append(f"     X509v3 Alternative Signature Value:")
                o.append(f"        ({len(raw)} bytes)")

        return o

    def _exts_verbose(self, cert) -> List[str]:
        o = []
        for ext in cert.extensions:
            crit = " critical" if ext.critical else ""
            o.append(f"     {ext_name(ext)}:{crit}")
            for line in ext_detail(ext):
                o.append(f"         {line}")
        return o

    def _fps(self, cert) -> List[str]:
        der = cert.public_bytes(serialization.Encoding.DER)
        return [
            f"  fp md5:    {format_fp(hashlib.md5(der, usedforsecurity=False).digest())}",
            f"  fp sha1:   {format_fp(hashlib.sha1(der, usedforsecurity=False).digest())}",
            f"  fp sha256: {format_fp(hashlib.sha256(der).digest())}",
        ]

    def _pub(self, cert) -> List[str]:
        o = []

        # Get the public key algorithm OID (works for all key types including PQC)
        pk_oid = None
        try:
            pk_oid = cert.public_key_algorithm_oid.dotted_string
        except AttributeError:
            pass

        # Subject Key Identifier lines (works regardless of key type)
        ski_lines = []
        try:
            ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ski_lines.append(f"    X509v3 Subject Key Identifier: ")
            ski_lines.append(f"        {format_fp(ski.value.digest)}")
        except x509.ExtensionNotFound: pass

        # Try to get the public key object
        try:
            key = cert.public_key()
        except (ValueError, UnsupportedAlgorithm):
            key = None

        if key is None:
            # PQC or unknown key type — show what we can from OID
            pqc = pqc_key_info(cert)
            algo = pub_key_algo(cert)
            if pqc:
                name, pub_bytes, sig_bytes, nist_level = pqc
                o.append("")
                o.append(f"  -> {name} public key  (PQC, NIST Level {nist_level})")
                o.append(f"    Public Key Algorithm: {name}")
                if pk_oid:
                    o.append(f"    Algorithm OID:   {pk_oid}")
                o.extend(ski_lines)
                o.append(f"    Public-Key: ({pub_bytes * 8} bit / {pub_bytes} bytes)")
                if sig_bytes:
                    o.append(f"    Signature size: {sig_bytes} bytes")
                o.append(f"    (Note: PQC key details require pyca/cryptography PQC support)")
            else:
                o.append("")
                o.append(f"  -> Unknown public key: {algo}")
                if pk_oid:
                    o.append(f"    Algorithm OID:   {pk_oid}")
                o.extend(ski_lines)

            # Show hybrid extension info if present
            hybrid = self._hybrid_info(cert)
            if hybrid:
                o.extend(hybrid)
            return o

        if isinstance(key, rsa.RSAPublicKey):
            o.append("")
            o.append("  -> RSA public key")
            o.append(f"    Public Key Algorithm: rsaEncryption")
            if pk_oid:
                o.append(f"    Algorithm OID:   {pk_oid}")
            o.extend(ski_lines)
            nums = key.public_numbers()
            o.append(f"    Public-Key: ({key.key_size} bit)")
            o.append(f"    Modulus:")
            h = format(nums.n, "x")
            if len(h) % 2: h = "0" + h
            pairs = [h[i:i+2] for i in range(0, len(h), 2)]
            preview = ":".join(pairs[:16])
            if len(pairs) > 16: preview += ":..."
            o.append(f"        {preview}")

        elif isinstance(key, ec.EllipticCurvePublicKey):
            o.append("")
            o.append("  -> ECC public key")
            o.append(f"    Public Key Algorithm: id-ecPublicKey")
            if pk_oid:
                o.append(f"    Algorithm OID:   {pk_oid}")
            o.extend(ski_lines)
            nm = {"secp256r1": ("prime256v1", "P-256"), "secp384r1": ("secp384r1", "P-384"), "secp521r1": ("secp521r1", "P-521")}
            o.append(f"    EC-Parameters: ({key.key_size} bit)")
            if key.curve.name in nm:
                a, n = nm[key.curve.name]
                o.append(f"    ASN1 OID: {a}")
                o.append(f"    NIST CURVE: {n}")
            else:
                o.append(f"    ASN1 OID: {key.curve.name}")

        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            algo = "ED25519" if isinstance(key, ed25519.Ed25519PublicKey) else "ED448"
            o.append("")
            o.append(f"  -> {algo} public key")
            o.append(f"    Public Key Algorithm: {algo}")
            if pk_oid:
                o.append(f"    Algorithm OID:   {pk_oid}")
            o.extend(ski_lines)

        else:
            o.append("")
            o.append(f"  -> Public key: {type(key).__name__}")

        # Public key fingerprint (matches key file output for cross-referencing)
        try:
            pub_der = key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            fp = format_fp(hashlib.sha256(pub_der).digest())
            o.append(f"    Public Key SHA-256:")
            o.append(f"       {fp}")
        except Exception:
            pass

        # Show hybrid extension info if present
        hybrid = self._hybrid_info(cert)
        if hybrid:
            o.extend(hybrid)

        return o

    def _hybrid_info(self, cert) -> List[str]:
        """Extract and format hybrid certificate extension info."""
        o = []
        has_hybrid = False
        for ext in cert.extensions:
            oid = ext.oid.dotted_string
            if oid in _HYBRID_EXT_NAMES:
                if not has_hybrid:
                    o.append("")
                    o.append("  -> Hybrid certificate extensions:")
                    has_hybrid = True
                name = _HYBRID_EXT_NAMES[oid]
                raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else b""
                if oid == "2.5.29.73":  # altSignatureAlgorithm
                    algo = _decode_algorithm_identifier(raw)
                    o.append(f"    {name}: {algo}")
                elif oid == "2.5.29.74":  # altSignatureValue
                    o.append(f"    {name}: ({len(raw)} bytes)")
                elif oid == "2.5.29.72":  # subjectAltPublicKeyInfo
                    algo = _decode_spki_algorithm(raw)
                    o.append(f"    {name}: {algo or 'present'} ({len(raw)} bytes)")
        return o

    def _full_text(self, cert) -> str:
        L = []
        L.append("    Data:")
        L.append(f"        Version: {cert.version.value + 1} (0x{cert.version.value})")
        L.append(f"        Serial Number:")
        L.append(f"            {format_serial(_get_serial(cert))}")
        L.append(f"        Signature Algorithm: {sig_algo_name(cert)}")
        L.append(f"        Issuer:  {format_dn_oneline(cert.issuer)}")
        L.append(f"        Validity")
        L.append(f"            Not Before: {format_dt(_not_before(cert))}")
        L.append(f"            Not After : {format_dt(_not_after(cert))}")
        L.append(f"        Subject: {format_dn_oneline(cert.subject)}")
        L.append(f"        Subject Public Key Info:")
        L.append(f"            Public Key Algorithm: {pub_key_algo(cert)}")

        try:
            key = cert.public_key()
        except (ValueError, UnsupportedAlgorithm):
            key = None

        if key is None:
            # PQC or unknown key type
            pqc = pqc_key_info(cert)
            if pqc:
                name, pub_bytes, sig_bytes, nist_level = pqc
                L.append(f"                {name} Public-Key: ({pub_bytes * 8} bit / {pub_bytes} bytes)")
                L.append(f"                NIST Security Level: {nist_level}")
                L.append(f"                (PQC key material not decodable by pyca/cryptography {crypto_version})")
            else:
                try:
                    pk_oid = cert.public_key_algorithm_oid.dotted_string
                    L.append(f"                Unknown key type: {pk_oid}")
                except AttributeError:
                    L.append(f"                Unable to decode public key")

        elif isinstance(key, rsa.RSAPublicKey):
            L.append(f"                Public-Key: ({key.key_size} bit)")
            nums = key.public_numbers()
            L.append(f"                Modulus:")
            h = format(nums.n, "x")
            if len(h) % 2: h = "0" + h
            pairs = [h[i:i+2] for i in range(0, len(h), 2)]
            for i in range(0, len(pairs), 15):
                chunk = ":".join(pairs[i:i+15])
                if i == 0 and int(pairs[0], 16) >= 0x80:
                    chunk = "00:" + chunk
                L.append(f"                    {chunk}")
            L.append(f"                Exponent: {nums.e} ({hex(nums.e)})")

        elif isinstance(key, ec.EllipticCurvePublicKey):
            L.append(f"                Public-Key: ({key.key_size} bit)")
            try:
                pub_bytes = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                L.append(f"                pub:")
                pairs = [f"{b:02x}" for b in pub_bytes]
                for i in range(0, len(pairs), 15):
                    L.append(f"                    {':'.join(pairs[i:i+15])}")
            except Exception:
                pass
            nm = {"secp256r1": "prime256v1", "secp384r1": "secp384r1", "secp521r1": "secp521r1"}
            L.append(f"                ASN1 OID: {nm.get(key.curve.name, key.curve.name)}")

        if cert.extensions:
            L.append(f"        X509v3 extensions:")
            for ext in cert.extensions:
                crit = " critical" if ext.critical else ""
                L.append(f"            {ext_name(ext)}:{crit}")
                for d in ext_detail_full(ext):
                    L.append(f"                {d}")

        L.append(f"    Signature Algorithm: {sig_algo_name(cert)}")
        L.append(f"    Signature Value:")
        pairs = [f"{b:02x}" for b in cert.signature]
        for i in range(0, len(pairs), 18):
            L.append(f"         {':'.join(pairs[i:i+18])}")

        return "\n".join(L)


# ---------------------------------------------------------------------------
#  CSR Formatter  (PKCS#10 Certificate Signing Requests)
# ---------------------------------------------------------------------------

class CsrFormatter:
    """Format CSR (PKCS#10) objects at various summary levels."""

    def __init__(self, verbose=0, show_pub=False, show_fp=False):
        self.verbose = verbose
        self.show_pub = show_pub
        self.show_fp = show_fp

    def format(self, csr, idx: int, level: str) -> str:
        method = getattr(self, f"_{level}", self._summary_1)
        return method(csr, idx)

    @staticmethod
    def _sig_valid(csr) -> str:
        """Return signature validity as string, handling PQC key types gracefully."""
        try:
            return str(csr.is_signature_valid)
        except (ValueError, UnsupportedAlgorithm):
            return "N/A (unsupported key type)"

    # ---- summary_0: compact one-liner style ----

    def _summary_0(self, csr, idx: int) -> str:
        o = [f"{idx}: Certificate Request:"]
        o.append(f"  {'Subject:':<19}  {dn_label(csr.subject)}")
        o.append(f"  Signature Algorithm: {sig_algo_name(csr)}")
        o.append(f"  Signature Valid:     {self._sig_valid(csr)}")
        if self.show_fp:
            o.append(""); o.extend(self._fps(csr))
        if self.show_pub:
            o.extend(self._pub(csr))
        return "\n".join(o)

    # ---- summary_1 (default): structured overview ----

    def _summary_1(self, csr, idx: int) -> str:
        o = [f"{idx}: Certificate Request:"]
        o.append(f"  Signature Algorithm: {sig_algo_name(csr)}")
        o.append(f"  - Public Key Algorithm: {pub_key_algo(csr)}")
        bits = pub_key_bits(csr)
        if bits: o.append(f"  - Public-Key: ({bits} bit)")
        o.extend(self._dn_block("Subject:", csr.subject))
        o.append("  Data:")
        o.append(f"     Version: 1 (0x0)")
        o.append(f"  Signature Valid: {self._sig_valid(csr)}")
        # Attributes & Requested Extensions
        o.extend(self._attrs_and_exts_summary(csr))
        if self.show_fp:
            o.append(""); o.extend(self._fps(csr))
        if self.show_pub:
            o.extend(self._pub(csr))
        return "\n".join(o)

    # ---- summary_2: all extensions verbose + fingerprints ----

    def _summary_2(self, csr, idx: int) -> str:
        o = [f"{idx}: Certificate Request:"]
        o.append(f"  Signature Algorithm: {sig_algo_name(csr)}")
        o.append(f"  - Public Key Algorithm: {pub_key_algo(csr)}")
        bits = pub_key_bits(csr)
        if bits: o.append(f"  - Public-Key: ({bits} bit)")
        o.extend(self._dn_block("Subject:", csr.subject))
        o.append("  Data:")
        o.append(f"     Version: 1 (0x0)")
        o.append(f"  Signature Valid: {self._sig_valid(csr)}")
        o.extend(self._attrs_and_exts_verbose(csr))
        o.append(""); o.extend(self._fps(csr))
        if self.show_pub:
            o.extend(self._pub(csr))
        return "\n".join(o)

    # ---- summary_3: full text, hex stripped  (matches Bash "summary") ----

    def _summary_3(self, csr, idx: int) -> str:
        o = [f"{idx}: Certificate Request:"]
        text = self._full_text(csr)
        skip_hex = False
        hex_shown = False
        for line in text.split("\n"):
            stripped = line.strip()
            if re.match(r'^\s*(Modulus:|Signature Value:|pub:)\s*$', line):
                skip_hex = True
                hex_shown = False
                o.append(line)
                continue
            if skip_hex and re.match(r'^[a-f0-9:]+\s*$', stripped) and len(stripped) >= 2:
                if not hex_shown:
                    m = re.match(r'^(\s*)', line)
                    o.append(f"{m.group(1) if m else '    '}...hex...")
                    hex_shown = True
                continue
            if skip_hex and not re.match(r'^[a-f0-9:]+\s*$', stripped):
                skip_hex = False
                hex_shown = False
            o.append(line)
        o.append(""); o.extend(self._fps(csr))
        if self.show_pub:
            o.extend(self._pub(csr))
        return "\n".join(o)

    # ---- summary_4: full text with hex  (matches Bash "full") ----

    def _summary_4(self, csr, idx: int) -> str:
        o = [f"{idx}: Certificate Request:"]
        o.append(self._full_text(csr))
        if self.show_fp:
            o.append(""); o.extend(self._fps(csr))
        if self.show_pub:
            o.extend(self._pub(csr))
        return "\n".join(o)

    # ---- DN block (reuse same style as CertFormatter) ----

    def _dn_block(self, label: str, name: x509.Name) -> List[str]:
        o = []
        comps = parse_dn(name)
        o.append(f"  {label:<8}")
        if "CN" in comps:
            o.append(f"           CN = {comps['CN']}")
        for tag in sorted(comps):
            if tag == "CN": continue
            o.append(f"           {tag:<2} = {comps[tag]}")
        return o

    # ---- Attributes & Extensions: summary (selected) ----

    def _attrs_and_exts_summary(self, csr) -> List[str]:
        o = []
        exts = list(csr.extensions)
        non_ext_attrs = [a for a in csr.attributes
                         if a.oid.dotted_string != "1.2.840.113549.1.9.14"]

        o.append("")
        o.append("  Attributes:")
        if not non_ext_attrs and not exts:
            o.append("     (none)")
        else:
            if non_ext_attrs:
                for attr in non_ext_attrs:
                    name = attr.oid._name
                    if name == "Unknown OID":
                        name = attr.oid.dotted_string
                    o.append(f"     {name}")

            if exts:
                o.append("     Requested Extensions:")
                # Key Usage
                try:
                    ku = csr.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                    crit = " critical" if ku.critical else ""
                    o.append(f"        X509v3 Key Usage:{crit}")
                    for u in sorted(key_usage_list(ku.value), key=str.lower):
                        o.append(f"           {u}")
                except x509.ExtensionNotFound: pass
                # Extended Key Usage
                try:
                    eku = csr.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
                    crit = " critical" if eku.critical else ""
                    o.append(f"        X509v3 Extended Key Usage:{crit}")
                    for u in sorted(eku.value, key=lambda u: u.dotted_string):
                        o.append(f"           {_EKU_NAMES.get(u.dotted_string, u._name or u.dotted_string)}")
                except x509.ExtensionNotFound: pass
                # Subject Alternative Name
                try:
                    san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    crit = " critical" if san_ext.critical else ""
                    o.append(f"        X509v3 Subject Alternative Name:{crit}")
                    for n in sorted(san_list(san_ext.value), key=str.lower):
                        o.append(f"           {n}")
                except x509.ExtensionNotFound: pass
                # Basic Constraints
                try:
                    bc = csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                    if bc.value.ca:
                        crit = " critical" if bc.critical else ""
                        o.append(f"        X509v3 Basic Constraints:{crit}")
                        o.append(f"           CA:TRUE")
                        if bc.value.path_length is not None:
                            o.append(f"           pathlen:{bc.value.path_length}")
                except x509.ExtensionNotFound: pass

        return o

    # ---- Attributes & Extensions: verbose (all) ----

    def _attrs_and_exts_verbose(self, csr) -> List[str]:
        o = []
        exts = list(csr.extensions)
        non_ext_attrs = [a for a in csr.attributes
                         if a.oid.dotted_string != "1.2.840.113549.1.9.14"]

        o.append("")
        o.append("  Attributes:")
        if not non_ext_attrs and not exts:
            o.append("     (none)")
        else:
            if non_ext_attrs:
                for attr in non_ext_attrs:
                    name = attr.oid._name
                    if name == "Unknown OID":
                        name = attr.oid.dotted_string
                    o.append(f"     {name}")

            if exts:
                o.append("     Requested Extensions:")
                for ext in exts:
                    crit = " critical" if ext.critical else ""
                    o.append(f"        {ext_name(ext)}:{crit}")
                    for line in ext_detail(ext):
                        o.append(f"            {line}")

        return o

    # ---- Fingerprints (on CSR DER bytes) ----

    def _fps(self, csr) -> List[str]:
        der = csr.public_bytes(serialization.Encoding.DER)
        return [
            f"  fp md5:    {format_fp(hashlib.md5(der, usedforsecurity=False).digest())}",
            f"  fp sha1:   {format_fp(hashlib.sha1(der, usedforsecurity=False).digest())}",
            f"  fp sha256: {format_fp(hashlib.sha256(der).digest())}",
        ]

    # ---- Public key info ----

    def _pub(self, csr) -> List[str]:
        o = []

        # Try to get the public key object
        try:
            key = csr.public_key()
        except (ValueError, UnsupportedAlgorithm):
            key = None

        if key is None:
            # PQC or unknown key type — show what we can from OID
            pqc = pqc_key_info(csr)
            algo = pub_key_algo(csr)
            if pqc:
                name, pub_bytes, sig_bytes, nist_level = pqc
                o.append("")
                o.append(f"  -> {name} public key  (PQC, NIST Level {nist_level})")
                o.append(f"    Public Key Algorithm: {name}")
                o.append(f"    Public-Key: ({pub_bytes * 8} bit / {pub_bytes} bytes)")
                if sig_bytes:
                    o.append(f"    Signature size: {sig_bytes} bytes")
                o.append(f"    (Note: PQC key details require pyca/cryptography PQC support)")
            else:
                o.append("")
                o.append(f"  -> Unknown public key: {algo}")
            return o

        if isinstance(key, rsa.RSAPublicKey):
            o.append("")
            o.append("  -> RSA public key")
            o.append(f"    Public Key Algorithm: rsaEncryption")
            nums = key.public_numbers()
            o.append(f"    Public-Key: ({key.key_size} bit)")
            o.append(f"    Modulus:")
            h = format(nums.n, "x")
            if len(h) % 2: h = "0" + h
            pairs = [h[i:i+2] for i in range(0, len(h), 2)]
            preview = ":".join(pairs[:16])
            if len(pairs) > 16: preview += ":..."
            o.append(f"        {preview}")

        elif isinstance(key, ec.EllipticCurvePublicKey):
            o.append("")
            o.append("  -> ECC public key")
            o.append(f"    Public Key Algorithm: id-ecPublicKey")
            nm = {"secp256r1": ("prime256v1", "P-256"), "secp384r1": ("secp384r1", "P-384"),
                  "secp521r1": ("secp521r1", "P-521")}
            o.append(f"    EC-Parameters: ({key.key_size} bit)")
            if key.curve.name in nm:
                a, n = nm[key.curve.name]
                o.append(f"    ASN1 OID: {a}")
                o.append(f"    NIST CURVE: {n}")
            else:
                o.append(f"    ASN1 OID: {key.curve.name}")

        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            algo = "ED25519" if isinstance(key, ed25519.Ed25519PublicKey) else "ED448"
            o.append("")
            o.append(f"  -> {algo} public key")
            o.append(f"    Public Key Algorithm: {algo}")

        else:
            o.append("")
            o.append(f"  -> Public key: {type(key).__name__}")

        # Public key fingerprint (matches key file output for cross-referencing)
        try:
            pub_der = key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            fp = format_fp(hashlib.sha256(pub_der).digest())
            o.append(f"    Public Key SHA-256:")
            o.append(f"       {fp}")
        except Exception:
            pass

        return o

    # ---- Full text (summary_3, summary_4) — matches OpenSSL `openssl req -text` ----

    def _full_text(self, csr) -> str:
        L = []
        L.append("    Data:")
        L.append(f"        Version: 1 (0x0)")
        L.append(f"        Subject: {format_dn_oneline(csr.subject)}")
        L.append(f"        Subject Public Key Info:")
        L.append(f"            Public Key Algorithm: {pub_key_algo(csr)}")

        try:
            key = csr.public_key()
        except (ValueError, UnsupportedAlgorithm):
            key = None

        if key is None:
            # PQC or unknown key type
            pqc = pqc_key_info(csr)
            if pqc:
                name, pub_bytes, sig_bytes, nist_level = pqc
                L.append(f"                {name} Public-Key: ({pub_bytes * 8} bit / {pub_bytes} bytes)")
                L.append(f"                NIST Security Level: {nist_level}")
                L.append(f"                (PQC key material not decodable by pyca/cryptography {crypto_version})")
            else:
                try:
                    pk_oid = csr.public_key_algorithm_oid.dotted_string
                    L.append(f"                Unknown key type: {pk_oid}")
                except AttributeError:
                    L.append(f"                Unable to decode public key")

        elif isinstance(key, rsa.RSAPublicKey):
            L.append(f"                Public-Key: ({key.key_size} bit)")
            nums = key.public_numbers()
            L.append(f"                Modulus:")
            h = format(nums.n, "x")
            if len(h) % 2: h = "0" + h
            pairs = [h[i:i+2] for i in range(0, len(h), 2)]
            for i in range(0, len(pairs), 15):
                chunk = ":".join(pairs[i:i+15])
                if i == 0 and int(pairs[0], 16) >= 0x80:
                    chunk = "00:" + chunk
                L.append(f"                    {chunk}")
            L.append(f"                Exponent: {nums.e} ({hex(nums.e)})")

        elif isinstance(key, ec.EllipticCurvePublicKey):
            L.append(f"                Public-Key: ({key.key_size} bit)")
            try:
                pub_bytes = key.public_bytes(serialization.Encoding.X962,
                                             serialization.PublicFormat.UncompressedPoint)
                L.append(f"                pub:")
                pairs = [f"{b:02x}" for b in pub_bytes]
                for i in range(0, len(pairs), 15):
                    L.append(f"                    {':'.join(pairs[i:i+15])}")
            except Exception:
                pass
            nm = {"secp256r1": "prime256v1", "secp384r1": "secp384r1", "secp521r1": "secp521r1"}
            L.append(f"                ASN1 OID: {nm.get(key.curve.name, key.curve.name)}")

        # Attributes
        exts = list(csr.extensions)
        non_ext_attrs = [a for a in csr.attributes
                         if a.oid.dotted_string != "1.2.840.113549.1.9.14"]

        L.append(f"        Attributes:")
        if not non_ext_attrs and not exts:
            L.append(f"            (none)")
        else:
            if non_ext_attrs:
                for attr in non_ext_attrs:
                    name = attr.oid._name
                    if name == "Unknown OID":
                        name = attr.oid.dotted_string
                    L.append(f"            {name}")

            if exts:
                L.append(f"            Requested Extensions:")
                for ext in exts:
                    crit = " critical" if ext.critical else ""
                    L.append(f"                {ext_name(ext)}:{crit}")
                    for d in ext_detail_full(ext):
                        L.append(f"                    {d}")

        L.append(f"    Signature Algorithm: {sig_algo_name(csr)}")
        L.append(f"    Signature Value:")
        pairs = [f"{b:02x}" for b in csr.signature]
        for i in range(0, len(pairs), 18):
            L.append(f"         {':'.join(pairs[i:i+18])}")

        return "\n".join(L)


# ---------------------------------------------------------------------------
#  Key Formatter  (Private Key safe summary)
# ---------------------------------------------------------------------------

class KeyFormatter:
    """Format private key safe summaries — never exposes private material."""

    def __init__(self, verbose=0, show_pub=False, show_fp=False):
        self.verbose = verbose
        self.show_pub = show_pub
        self.show_fp = show_fp

    def format(self, key_info: dict, idx: int, level: str) -> str:
        method = getattr(self, f"_{level}", self._summary_1)
        return method(key_info, idx)

    @staticmethod
    def _key_type_label(ki: dict) -> str:
        """Return a human-readable key type string from key object or OID."""
        key = ki.get("key")
        if key is not None:
            if isinstance(key, rsa.RSAPrivateKey):            return "RSA"
            if isinstance(key, ec.EllipticCurvePrivateKey):   return "EC"
            if isinstance(key, ed25519.Ed25519PrivateKey):    return "Ed25519"
            if isinstance(key, ed448.Ed448PrivateKey):        return "Ed448"
            if isinstance(key, dsa.DSAPrivateKey):            return "DSA"
            if isinstance(key, x25519.X25519PrivateKey):      return "X25519"
            if isinstance(key, x448.X448PrivateKey):          return "X448"
            return type(key).__name__
        # Fallback to OID-derived name
        oid_name = ki.get("oid_name")
        if oid_name:
            return oid_name
        return "Unknown"

    @staticmethod
    def _key_bits(ki: dict) -> Optional[int]:
        """Return key size in bits from key object or PQC table."""
        key = ki.get("key")
        if key is not None:
            if isinstance(key, rsa.RSAPrivateKey):            return key.key_size
            if isinstance(key, ec.EllipticCurvePrivateKey):   return key.key_size
            if isinstance(key, ed25519.Ed25519PrivateKey):    return 256
            if isinstance(key, ed448.Ed448PrivateKey):        return 456
            if isinstance(key, dsa.DSAPrivateKey):            return key.key_size
            if isinstance(key, x25519.X25519PrivateKey):      return 256
            if isinstance(key, x448.X448PrivateKey):          return 448
            return None
        # Fallback: PQC table has key size in bytes (public key size)
        pqc = ki.get("pqc_info")
        if pqc:
            return pqc[1] * 8
        return None

    def _pub_fingerprint(self, pub) -> Optional[str]:
        """SHA-256 fingerprint of the DER-encoded public key (for cert matching)."""
        if pub is None:
            return None
        try:
            pub_der = pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return format_fp(hashlib.sha256(pub_der).digest())
        except Exception:
            return None

    def _summary_0(self, ki: dict, idx: int) -> str:
        """Short: type, size, encryption status."""
        key, pub = ki["key"], ki["pub"]
        o = [f"{idx}: Private Key:"]
        o.append(f"  *** PRIVATE KEY — handle with care ***")
        ktype = self._key_type_label(ki)
        bits = self._key_bits(ki)

        if ki["encrypted"]:
            o.append(f"  Key Type:        (encrypted — cannot inspect without passphrase)")
            o.append(f"  PEM Format:      {ki['pem_format']}")
        else:
            o.append(f"  Key Type:        {ktype}")
            if bits:
                o.append(f"  Key Size:        {bits} bit")
            if isinstance(key, ec.EllipticCurvePrivateKey):
                cname = key.curve.name
                display = _EC_CURVE_DISPLAY.get(cname, (cname, cname))
                o.append(f"  Curve:           {display[1]}  ({display[0]})")
            pqc = ki.get("pqc_info")
            if pqc:
                o.append(f"  PQC:             NIST Level {pqc[3]}")
        return "\n".join(o)

    def _summary_1(self, ki: dict, idx: int) -> str:
        """Default: type, size, format, curve, public key fingerprint."""
        key, pub = ki["key"], ki["pub"]
        o = [f"{idx}: Private Key:"]
        o.append(f"  *** PRIVATE KEY — handle with care ***")
        ktype = self._key_type_label(ki)
        bits = self._key_bits(ki)

        if ki["encrypted"]:
            o.append(f"  Key Type:        (encrypted — cannot inspect without passphrase)")
            o.append(f"  PEM Format:      {ki['pem_format']}")
            o.append(f"  Decryption:      Supply passphrase to inspect key properties")
            return "\n".join(o)

        o.append(f"  Key Type:        {ktype}")
        if bits:
            o.append(f"  Key Size:        {bits} bit")
        o.append(f"  PEM Format:      {ki['pem_format']}")

        # Show OID — from OID fallback (PQC) or derived from key type
        oid = ki.get("oid") or _key_algo_oid(key)
        if oid:
            oid_name = ki.get("oid_name") or _pubkey_oid_name(oid)
            o.append(f"  Algorithm OID:   {oid}  ({oid_name})")

        if isinstance(key, ec.EllipticCurvePrivateKey):
            cname = key.curve.name
            display = _EC_CURVE_DISPLAY.get(cname, (cname, cname))
            o.append(f"  Curve:           {display[1]}  ({display[0]})")
            o.append(f"  ASN1 OID:        {display[0]}")
        elif isinstance(key, rsa.RSAPrivateKey):
            nums = pub.public_numbers()
            o.append(f"  Public Exponent: {nums.e}  ({hex(nums.e)})")

        # PQC details
        pqc = ki.get("pqc_info")
        if pqc:
            name, pub_bytes, sig_bytes, nist_level = pqc
            o.append(f"  PQC:             NIST Level {nist_level}")
            o.append(f"  Public Key Size: {pub_bytes} bytes ({pub_bytes * 8} bit)")
            if sig_bytes:
                o.append(f"  Signature Size:  {sig_bytes} bytes")
            if key is None:
                o.append(f"  (Note: PQC key details require pyca/cryptography PQC support)")

        fp = self._pub_fingerprint(pub)
        if fp:
            o.append(f"  Public Key SHA-256:")
            o.append(f"     {fp}")
            o.append(f"     (Use this to match against certificates)")

        if self.show_fp and pub:
            o.extend(self._pub_fps(pub))
        if self.show_pub and pub:
            o.extend(self._pub_details(key, pub))
        return "\n".join(o)

    def _summary_2(self, ki: dict, idx: int) -> str:
        """Verbose: adds all fingerprints and public key details."""
        key, pub = ki["key"], ki["pub"]
        o = [self._summary_1(ki, idx)]
        if not ki["encrypted"] and pub:
            if not self.show_fp:
                o.extend(self._pub_fps(pub))
            if not self.show_pub:
                o.extend(self._pub_details(key, pub))
        return "\n".join(o)

    def _summary_3(self, ki: dict, idx: int) -> str:
        """Same as summary_2 for keys (keys have no extensions/DN to expand)."""
        return self._summary_2(ki, idx)

    def _summary_4(self, ki: dict, idx: int) -> str:
        """Full: same as summary_2 for keys."""
        return self._summary_2(ki, idx)

    def _pub_fps(self, pub) -> List[str]:
        """Public key fingerprints (MD5, SHA-1, SHA-256 of SPKI DER)."""
        o = []
        try:
            pub_der = pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            o.append("")
            o.append("  Public key fingerprints (of SubjectPublicKeyInfo DER):")
            o.append(f"    fp md5:    {format_fp(hashlib.md5(pub_der, usedforsecurity=False).digest())}")
            o.append(f"    fp sha1:   {format_fp(hashlib.sha1(pub_der, usedforsecurity=False).digest())}")
            o.append(f"    fp sha256: {format_fp(hashlib.sha256(pub_der).digest())}")
        except Exception:
            pass
        return o

    def _pub_details(self, key, pub) -> List[str]:
        """Public key details (safe to show — this is the public component)."""
        o = []
        if isinstance(key, rsa.RSAPrivateKey):
            nums = pub.public_numbers()
            o.append("")
            o.append("  -> RSA public component")
            o.append(f"    Public-Key: ({key.key_size} bit)")
            o.append(f"    Exponent: {nums.e} ({hex(nums.e)})")
            o.append(f"    Modulus (first 16 bytes):")
            h = format(nums.n, "x")
            if len(h) % 2: h = "0" + h
            pairs = [h[i:i+2] for i in range(0, len(h), 2)]
            preview = ":".join(pairs[:16])
            o.append(f"        {preview}:...")

        elif isinstance(key, ec.EllipticCurvePrivateKey):
            o.append("")
            o.append("  -> EC public component")
            o.append(f"    Public-Key: ({key.key_size} bit)")
            cname = key.curve.name
            display = _EC_CURVE_DISPLAY.get(cname, (cname, cname))
            o.append(f"    ASN1 OID: {display[0]}")
            o.append(f"    NIST CURVE: {display[1]}")
            try:
                pub_bytes = pub.public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
                pairs = [f"{b:02x}" for b in pub_bytes]
                preview = ":".join(pairs[:16])
                if len(pairs) > 16:
                    preview += ":..."
                o.append(f"    pub (first 16 bytes):")
                o.append(f"        {preview}")
            except Exception:
                pass

        elif isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            algo = "Ed25519" if isinstance(key, ed25519.Ed25519PrivateKey) else "Ed448"
            o.append("")
            o.append(f"  -> {algo} public component")
            try:
                raw = pub.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                pairs = [f"{b:02x}" for b in raw]
                o.append(f"    pub: {':'.join(pairs)}")
            except Exception:
                pass

        elif isinstance(key, dsa.DSAPrivateKey):
            o.append("")
            o.append("  -> DSA public component")
            o.append(f"    Public-Key: ({key.key_size} bit)")

        return o


# ---------------------------------------------------------------------------
#  Public Key Formatter  (standalone public key inspection)
# ---------------------------------------------------------------------------

class PublicKeyFormatter:
    """Format public key summaries for standalone .pub / public key files."""

    def __init__(self, verbose=0, show_pub=False, show_fp=False):
        self.verbose = verbose
        self.show_pub = show_pub
        self.show_fp = show_fp

    def format(self, pub_info: dict, idx: int, level: str) -> str:
        method = getattr(self, f"_{level}", self._summary_1)
        return method(pub_info, idx)

    @staticmethod
    def _key_type_label(pi: dict) -> str:
        """Return a human-readable key type string from pub object or OID."""
        pub = pi.get("pub")
        if pub is not None:
            if isinstance(pub, rsa.RSAPublicKey):            return "RSA"
            if isinstance(pub, ec.EllipticCurvePublicKey):   return "EC"
            if isinstance(pub, ed25519.Ed25519PublicKey):    return "Ed25519"
            if isinstance(pub, ed448.Ed448PublicKey):        return "Ed448"
            if isinstance(pub, dsa.DSAPublicKey):            return "DSA"
            if isinstance(pub, x25519.X25519PublicKey):      return "X25519"
            if isinstance(pub, x448.X448PublicKey):          return "X448"
            return type(pub).__name__
        # Fallback to OID-derived name
        oid_name = pi.get("oid_name")
        if oid_name:
            return oid_name
        return "Unknown"

    @staticmethod
    def _key_bits(pi: dict) -> Optional[int]:
        """Return key size in bits from pub object or PQC table."""
        pub = pi.get("pub")
        if pub is not None:
            if isinstance(pub, rsa.RSAPublicKey):            return pub.key_size
            if isinstance(pub, ec.EllipticCurvePublicKey):   return pub.key_size
            if isinstance(pub, ed25519.Ed25519PublicKey):    return 256
            if isinstance(pub, ed448.Ed448PublicKey):        return 456
            if isinstance(pub, dsa.DSAPublicKey):            return pub.key_size
            if isinstance(pub, x25519.X25519PublicKey):      return 256
            if isinstance(pub, x448.X448PublicKey):          return 448
            return None
        # Fallback: PQC table has key size in bytes
        pqc = pi.get("pqc_info")
        if pqc:
            return pqc[1] * 8  # bytes to bits
        return None

    def _der_fingerprint(self, pi: dict) -> Optional[str]:
        """SHA-256 fingerprint of the DER-encoded public key."""
        pub = pi.get("pub")
        if pub is not None:
            try:
                pub_der = pub.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                return format_fp(hashlib.sha256(pub_der).digest())
            except Exception:
                pass
        # Fallback: use raw DER from SPKI parse
        key_der = pi.get("key_der")
        if key_der:
            return format_fp(hashlib.sha256(key_der).digest())
        return None

    def _summary_0(self, pi: dict, idx: int) -> str:
        """Short: type and size."""
        pub = pi.get("pub")
        o = [f"{idx}: Public Key:"]
        ktype = self._key_type_label(pi)
        bits = self._key_bits(pi)

        o.append(f"  Key Type:        {ktype}")
        if bits:
            o.append(f"  Key Size:        {bits} bit")
        if isinstance(pub, ec.EllipticCurvePublicKey):
            cname = pub.curve.name
            display = _EC_CURVE_DISPLAY.get(cname, (cname, cname))
            o.append(f"  Curve:           {display[1]}  ({display[0]})")
        # PQC info
        pqc = pi.get("pqc_info")
        if pqc:
            name, pub_bytes, sig_bytes, nist_level = pqc
            o.append(f"  PQC:             NIST Level {nist_level}")
        return "\n".join(o)

    def _summary_1(self, pi: dict, idx: int) -> str:
        """Default: type, size, OID, format, curve, PQC info, fingerprint."""
        pub = pi.get("pub")
        o = [f"{idx}: Public Key:"]
        ktype = self._key_type_label(pi)
        bits = self._key_bits(pi)

        o.append(f"  Key Type:        {ktype}")
        if bits:
            o.append(f"  Key Size:        {bits} bit")
        o.append(f"  PEM Format:      {pi['pem_format']}")

        # Always show OID — from OID fallback (PQC) or derived from key type
        oid = pi.get("oid") or _key_algo_oid(pub)
        if oid:
            oid_name = pi.get("oid_name") or _pubkey_oid_name(oid)
            o.append(f"  Algorithm OID:   {oid}  ({oid_name})")

        if isinstance(pub, ec.EllipticCurvePublicKey):
            cname = pub.curve.name
            display = _EC_CURVE_DISPLAY.get(cname, (cname, cname))
            o.append(f"  Curve:           {display[1]}  ({display[0]})")
            o.append(f"  ASN1 OID:        {display[0]}")
        elif isinstance(pub, rsa.RSAPublicKey):
            nums = pub.public_numbers()
            o.append(f"  Public Exponent: {nums.e}  ({hex(nums.e)})")

        # PQC details
        pqc = pi.get("pqc_info")
        if pqc:
            name, pub_bytes, sig_bytes, nist_level = pqc
            o.append(f"  PQC:             NIST Level {nist_level}")
            o.append(f"  Public Key Size: {pub_bytes} bytes ({pub_bytes * 8} bit)")
            if sig_bytes:
                o.append(f"  Signature Size:  {sig_bytes} bytes")
            if pub is None:
                o.append(f"  (Note: PQC key details require pyca/cryptography PQC support)")

        fp = self._der_fingerprint(pi)
        if fp:
            o.append(f"  Public Key SHA-256:")
            o.append(f"     {fp}")
            o.append(f"     (Use this to match against certificates or private keys)")

        if self.show_fp:
            o.extend(self._der_fps(pi))
        if self.show_pub and pub:
            o.extend(self._pub_details(pub))
        return "\n".join(o)

    def _summary_2(self, pi: dict, idx: int) -> str:
        """Verbose: adds all fingerprints and public key hex."""
        pub = pi.get("pub")
        o = [self._summary_1(pi, idx)]
        if not self.show_fp:
            o.extend(self._der_fps(pi))
        if not self.show_pub and pub:
            o.extend(self._pub_details(pub))
        return "\n".join(o)

    def _summary_3(self, pi: dict, idx: int) -> str:
        return self._summary_2(pi, idx)

    def _summary_4(self, pi: dict, idx: int) -> str:
        return self._summary_2(pi, idx)

    def _der_fps(self, pi: dict) -> List[str]:
        """Public key fingerprints (MD5, SHA-1, SHA-256 of SPKI DER)."""
        o = []
        pub_der = None
        pub = pi.get("pub")
        if pub is not None:
            try:
                pub_der = pub.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            except Exception:
                pass
        if pub_der is None:
            pub_der = pi.get("key_der")
        if pub_der:
            o.append("")
            o.append("  Public key fingerprints (of SubjectPublicKeyInfo DER):")
            o.append(f"    fp md5:    {format_fp(hashlib.md5(pub_der, usedforsecurity=False).digest())}")
            o.append(f"    fp sha1:   {format_fp(hashlib.sha1(pub_der, usedforsecurity=False).digest())}")
            o.append(f"    fp sha256: {format_fp(hashlib.sha256(pub_der).digest())}")
        return o

    def _pub_details(self, pub) -> List[str]:
        """Public key details — hex dump of public component."""
        o = []
        if isinstance(pub, rsa.RSAPublicKey):
            nums = pub.public_numbers()
            o.append("")
            o.append("  -> RSA public component")
            o.append(f"    Public-Key: ({pub.key_size} bit)")
            o.append(f"    Exponent: {nums.e} ({hex(nums.e)})")
            o.append(f"    Modulus:")
            h = format(nums.n, "x")
            if len(h) % 2: h = "0" + h
            pairs = [h[i:i+2] for i in range(0, len(h), 2)]
            for i in range(0, len(pairs), 18):
                o.append(f"        {':'.join(pairs[i:i+18])}")

        elif isinstance(pub, ec.EllipticCurvePublicKey):
            o.append("")
            o.append("  -> EC public component")
            o.append(f"    Public-Key: ({pub.key_size} bit)")
            cname = pub.curve.name
            display = _EC_CURVE_DISPLAY.get(cname, (cname, cname))
            o.append(f"    ASN1 OID: {display[0]}")
            o.append(f"    NIST CURVE: {display[1]}")
            try:
                pub_bytes = pub.public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
                pairs = [f"{b:02x}" for b in pub_bytes]
                o.append(f"    pub:")
                for i in range(0, len(pairs), 18):
                    o.append(f"        {':'.join(pairs[i:i+18])}")
            except Exception:
                pass

        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            algo = "Ed25519" if isinstance(pub, ed25519.Ed25519PublicKey) else "Ed448"
            o.append("")
            o.append(f"  -> {algo} public component")
            try:
                raw = pub.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                pairs = [f"{b:02x}" for b in raw]
                o.append(f"    pub: {':'.join(pairs)}")
            except Exception:
                pass

        elif isinstance(pub, dsa.DSAPublicKey):
            o.append("")
            o.append("  -> DSA public component")
            o.append(f"    Public-Key: ({pub.key_size} bit)")

        return o


# ---------------------------------------------------------------------------
#  CRL Formatter
# ---------------------------------------------------------------------------

# Revocation reason display names
_CRL_REASON_NAMES = {
    x509.ReasonFlags.unspecified:              "Unspecified",
    x509.ReasonFlags.key_compromise:           "Key Compromise",
    x509.ReasonFlags.ca_compromise:            "CA Compromise",
    x509.ReasonFlags.affiliation_changed:      "Affiliation Changed",
    x509.ReasonFlags.superseded:               "Superseded",
    x509.ReasonFlags.cessation_of_operation:   "Cessation Of Operation",
    x509.ReasonFlags.certificate_hold:         "Certificate Hold",
    x509.ReasonFlags.privilege_withdrawn:      "Privilege Withdrawn",
    x509.ReasonFlags.aa_compromise:            "AA Compromise",
    x509.ReasonFlags.remove_from_crl:          "Remove From CRL",
}


class CrlFormatter:
    """Format X.509 CRL summaries."""

    def __init__(self, verbose=0, show_pub=False, show_fp=False):
        self.verbose = verbose
        self.show_pub = show_pub
        self.show_fp = show_fp

    def format(self, crl, idx: int, level: str) -> str:
        method = getattr(self, f"_{level}", self._summary_1)
        return method(crl, idx)

    @staticmethod
    def _revoked_count(crl) -> int:
        return len(list(crl))

    @staticmethod
    def _revoked_entry(rc) -> str:
        """Format one revoked certificate entry."""
        serial = format_serial(rc.serial_number)
        date = format_dt(_revocation_date(rc))
        reason = ""
        for ext in rc.extensions:
            if isinstance(ext.value, x509.CRLReason):
                reason = _CRL_REASON_NAMES.get(ext.value.reason, str(ext.value.reason))
        if reason:
            return f"     {serial:<45s}  {date}  ({reason})"
        return f"     {serial:<45s}  {date}"

    def _crl_exts(self, crl) -> List[str]:
        """Format CRL extensions."""
        o = []
        for ext in crl.extensions:
            val = ext.value
            name = ext_name(ext)
            crit = " critical" if ext.critical else ""

            if isinstance(val, x509.CRLNumber):
                o.append(f"     {name}:{crit}")
                o.append(f"         {val.crl_number}")
            elif isinstance(val, x509.DeltaCRLIndicator):
                o.append(f"     {name}:{crit}")
                o.append(f"         {val.crl_number}")
            elif isinstance(val, x509.AuthorityKeyIdentifier):
                o.append(f"     {name}:{crit}")
                if val.key_identifier:
                    o.append(f"         {format_fp(val.key_identifier)}")
            elif isinstance(val, x509.IssuingDistributionPoint):
                o.append(f"     {name}:{crit}")
                if val.full_name:
                    o.append("         Full Name:")
                    for n in val.full_name:
                        o.append(f"           URI:{n.value}")
                if val.only_contains_user_certs:
                    o.append("         Only User Certificates")
                if val.only_contains_ca_certs:
                    o.append("         Only CA Certificates")
                if val.only_some_reasons:
                    reasons = ", ".join(
                        _CRL_REASON_NAMES.get(r, str(r))
                        for r in val.only_some_reasons
                    )
                    o.append(f"         Only Some Reasons: {reasons}")
            elif isinstance(val, (x509.AuthorityInformationAccess,)):
                o.append(f"     {name}:{crit}")
                for desc in val:
                    method = ("OCSP" if desc.access_method
                              == x509.oid.AuthorityInformationAccessOID.OCSP
                              else "CA Issuers")
                    o.append(f"         {method} - URI:{desc.access_location.value}")
            else:
                o.append(f"     {name}:{crit}")
                lines = ext_detail(ext)
                for line in lines:
                    o.append(f"         {line}")
        return o

    def _fps(self, crl) -> List[str]:
        """CRL fingerprints."""
        return [
            f"  fp md5:    {format_fp(crl.fingerprint(hashes.MD5()))}",
            f"  fp sha1:   {format_fp(crl.fingerprint(hashes.SHA1()))}",
            f"  fp sha256: {format_fp(crl.fingerprint(hashes.SHA256()))}",
        ]

    def _summary_0(self, crl, idx: int) -> str:
        n_revoked = self._revoked_count(crl)
        o = [f"{idx}: Certificate Revocation List:"]
        o.append(f"  {'Issuer:':<15}  {dn_label(crl.issuer)}")
        o.append(f"  {'Last Update:':<15}  {format_dt(_last_update(crl))}")
        o.append(f"  {'Next Update:':<15}  {format_dt(_next_update(crl))}")
        o.append(f"  {'Revoked:':<15}  {n_revoked} certificate(s)")
        if self.show_fp:
            o.append("")
            o.extend(self._fps(crl))
        return "\n".join(o)

    def _summary_1(self, crl, idx: int) -> str:
        n_revoked = self._revoked_count(crl)
        o = [f"{idx}: Certificate Revocation List:"]
        o.append(f"  Signature Algorithm: {crl.signature_algorithm_oid._name}")

        # Issuer DN
        o.extend(self._dn_block("Issuer:", crl.issuer))

        o.append(f"  Last Update: {format_dt(_last_update(crl))}")
        o.append(f"  Next Update: {format_dt(_next_update(crl))}")

        # CRL Number (if present)
        try:
            crl_num = crl.extensions.get_extension_for_class(x509.CRLNumber)
            o.append(f"  CRL Number:  {crl_num.value.crl_number}")
        except x509.ExtensionNotFound:
            pass

        o.append(f"  Revoked Certificates: {n_revoked}")

        # At level 1, show first 10 revoked entries as a preview
        if n_revoked > 0:
            revoked = list(crl)
            show = revoked[:10]
            o.append("  Revoked:")
            o.append(f"     {'Serial Number':<45s}  {'Revocation Date':<28s}")
            for rc in show:
                o.append(self._revoked_entry(rc))
            if n_revoked > 10:
                o.append(f"     ... and {n_revoked - 10} more")

        if self.show_fp:
            o.append("")
            o.extend(self._fps(crl))
        return "\n".join(o)

    def _summary_2(self, crl, idx: int) -> str:
        n_revoked = self._revoked_count(crl)
        o = [f"{idx}: Certificate Revocation List:"]
        o.append(f"  Signature Algorithm: {crl.signature_algorithm_oid._name}")
        o.extend(self._dn_block("Issuer:", crl.issuer))
        o.append(f"  Last Update: {format_dt(_last_update(crl))}")
        o.append(f"  Next Update: {format_dt(_next_update(crl))}")

        # CRL extensions
        ext_lines = self._crl_exts(crl)
        if ext_lines:
            o.append("")
            o.append("  CRL extensions:")
            o.extend(ext_lines)

        # All revoked entries
        o.append("")
        o.append(f"  Revoked Certificates: {n_revoked}")
        if n_revoked > 0:
            o.append(f"     {'Serial Number':<45s}  {'Revocation Date':<28s}")
            for rc in crl:
                o.append(self._revoked_entry(rc))

        o.append("")
        o.extend(self._fps(crl))

        return "\n".join(o)

    # summary_3 and summary_4 use the same full display as summary_2
    def _summary_3(self, crl, idx: int) -> str:
        return self._summary_2(crl, idx)

    def _summary_4(self, crl, idx: int) -> str:
        return self._summary_2(crl, idx)

    @staticmethod
    def _dn_block(label, name) -> List[str]:
        """Format a DN block, same pattern as CertFormatter."""
        parsed = parse_dn(name)
        if len(parsed) <= 2:
            oneline = format_dn_oneline(name)
            return [f"  {label} {oneline}"]
        o = [f"  {label} "]
        for key, val in parsed.items():
            o.append(f"           {key} = {val}")
        return o


# ---------------------------------------------------------------------------
#  Chain Verification
# ---------------------------------------------------------------------------

class ChainVerifier:
    """Verify internal consistency of an X.509 certificate chain.

    Performs offline checks (no network, no trust store):
      - Chain linkage (Subject ↔ Issuer DN matching)
      - Signature verification (each cert signed by its issuer)
      - Validity period (not-before / not-after date checks)
      - basicConstraints (CA:TRUE on issuing certs)
      - keyUsage (keyCertSign on issuing certs)
      - pathLength constraint enforcement

    Does NOT check: trust anchors, revocation (CRL/OCSP), name constraints,
    policy constraints, or extended key usage.
    """

    def __init__(self, certs: list):
        """Initialize with a list of x509.Certificate objects."""
        self._certs = list(certs)
        self._now = datetime.datetime.now(datetime.timezone.utc)
        self._ordered = []    # leaf → ... → root
        self._errors = []     # list of (index, message)
        self._warnings = []   # list of (index, message)
        self._status = {}     # index → list of (symbol, message)
        self._result = None   # "consistent" / "N error(s)" / etc.

    def verify(self) -> dict:
        """Run verification and return structured result.

        Returns dict with:
            ordered:  list of x509.Certificate (leaf → root order)
            chain:    list of per-cert dicts with label, checks
            errors:   int — total error count
            warnings: int — total warning count
            result:   str — summary line
        """
        if not self._certs:
            return {"ordered": [], "chain": [], "errors": 0,
                    "warnings": 0, "result": "empty chain"}

        if len(self._certs) == 1:
            return self._verify_single()

        self._order_chain()
        self._check_all()
        return self._build_result()

    # --- Chain ordering ---------------------------------------------------

    def _order_chain(self):
        """Order certs from leaf to root by Subject/Issuer matching."""
        certs = list(self._certs)

        # Build lookup: subject DN bytes → cert
        by_subject = {}
        for c in certs:
            key = c.subject.public_bytes()
            by_subject.setdefault(key, []).append(c)

        # Find leaf candidates: certs whose issuer != own subject (not self-signed)
        # and that are NOT the issuer of any other cert
        issuer_subjects = set()
        for c in certs:
            issuer_subjects.add(c.issuer.public_bytes())

        leaves = []
        for c in certs:
            subj = c.subject.public_bytes()
            is_self_signed = (subj == c.issuer.public_bytes())
            is_issuer_of_others = subj in {
                oc.issuer.public_bytes() for oc in certs if oc is not c
            }
            if not is_self_signed and not is_issuer_of_others:
                leaves.append(c)

        # If no clear leaf, pick the first non-self-signed, or just first cert
        if not leaves:
            for c in certs:
                if c.subject.public_bytes() != c.issuer.public_bytes():
                    leaves = [c]
                    break
            if not leaves:
                leaves = [certs[0]]

        # Walk from leaf up to root
        ordered = [leaves[0]]
        used = {id(leaves[0])}
        current = leaves[0]

        for _ in range(len(certs)):
            issuer_key = current.issuer.public_bytes()
            # Self-signed? We're at the root
            if current.subject.public_bytes() == issuer_key:
                break
            # Find the issuer
            candidates = by_subject.get(issuer_key, [])
            parent = None
            for c in candidates:
                if id(c) not in used:
                    parent = c
                    break
            if parent is None:
                break  # Incomplete chain
            ordered.append(parent)
            used.add(id(parent))
            current = parent

        # Append any remaining certs not in chain (disjoint/extra)
        for c in certs:
            if id(c) not in used:
                ordered.append(c)

        self._ordered = ordered
        self._linked_ids = used  # certs that are part of the actual chain walk

    # --- Per-link verification --------------------------------------------

    def _check_all(self):
        """Run all checks on the ordered chain."""
        chain = self._ordered
        linked = self._linked_ids
        for i, cert in enumerate(chain):
            checks = []
            cn = self._cert_cn(cert)
            is_self_signed = (cert.subject.public_bytes() ==
                              cert.issuer.public_bytes())
            is_linked = id(cert) in linked
            is_last_linked = is_linked and (
                i == len(chain) - 1 or id(chain[i + 1]) not in linked)

            # --- Validity period ---
            if self._now < cert.not_valid_before_utc:
                checks.append(("x", f"NOT YET VALID (starts {format_dt(cert.not_valid_before_utc)})"))
                self._errors.append((i, "not yet valid"))
            elif self._now > cert.not_valid_after_utc:
                checks.append(("x", f"EXPIRED ({format_dt(cert.not_valid_after_utc)})"))
                self._errors.append((i, "expired"))
            else:
                checks.append(("+", f"Valid (expires {format_dt(cert.not_valid_after_utc)})"))

            # --- Disjoint self-signed certs: validity + self-sig only ---
            if not is_linked and is_self_signed:
                ok, msg = self._verify_sig(cert, cert)
                if ok is True:
                    checks.append(("+", "Self-signed"))
                elif ok is None:
                    checks.append(("!", f"Self-signed (signature not checked: {msg})"))
                    self._warnings.append((i, "signature not checked"))
                else:
                    checks.append(("x", "SELF-SIGNED SIGNATURE INVALID"))
                    self._errors.append((i, "self-signed signature invalid"))
                self._status[i] = checks
                continue

            # --- Disjoint non-self-signed: find issuer in chain ---
            if not is_linked and not is_self_signed:
                issuer_key = cert.issuer.public_bytes()
                found_issuer = None
                for c in chain:
                    if c.subject.public_bytes() == issuer_key and c is not cert:
                        found_issuer = c
                        break
                if found_issuer:
                    issuer_cn = self._cert_cn(found_issuer)
                    ok, msg = self._verify_sig(cert, found_issuer)
                    if ok is True:
                        checks.append(("+", f"Signed by {issuer_cn}"))
                    elif ok is None:
                        checks.append(("!", f"Signed by {issuer_cn} (signature not checked: {msg})"))
                        self._warnings.append((i, "signature not checked"))
                    else:
                        checks.append(("x", f"SIGNATURE INVALID (issuer {issuer_cn})"))
                        self._errors.append((i, "signature verification failed"))
                else:
                    checks.append(("!", "Issuer not in chain (incomplete)"))
                    self._warnings.append((i, "issuer not in chain"))
                self._status[i] = checks
                continue

            # --- Signature verification (linked chain certs) ---
            if is_self_signed:
                ok, msg = self._verify_sig(cert, cert)
                if ok is True:
                    checks.append(("+", "Self-signed"))
                elif ok is None:
                    checks.append(("!", f"Self-signed (signature not checked: {msg})"))
                    self._warnings.append((i, "signature not checked"))
                else:
                    checks.append(("x", "SELF-SIGNED SIGNATURE INVALID"))
                    self._errors.append((i, "self-signed signature invalid"))
            elif i + 1 < len(chain) and id(chain[i + 1]) in linked:
                issuer = chain[i + 1]
                issuer_cn = self._cert_cn(issuer)
                # Check issuer DN match first
                if cert.issuer.public_bytes() != issuer.subject.public_bytes():
                    checks.append(("x", f"ISSUER MISMATCH (expected '{issuer_cn}')"))
                    self._errors.append((i, "issuer DN mismatch"))
                else:
                    ok, msg = self._verify_sig(cert, issuer)
                    if ok is True:
                        checks.append(("+", f"Signed by {issuer_cn}"))
                    elif ok is None:
                        checks.append(("!", f"Signed by {issuer_cn} (signature not checked: {msg})"))
                        self._warnings.append((i, "signature not checked"))
                    else:
                        checks.append(("x", f"SIGNATURE INVALID (claimed issuer {issuer_cn})"))
                        self._errors.append((i, "signature verification failed"))
            else:
                # No issuer available
                if not is_self_signed:
                    checks.append(("!", "Issuer not in chain (incomplete)"))
                    self._warnings.append((i, "issuer not in chain"))

            # --- Issuer CA checks (for certs signed by others in chain) ---
            if i + 1 < len(chain) and not is_self_signed and is_linked and id(chain[i + 1]) in linked:
                issuer = chain[i + 1]
                issuer_cn = self._cert_cn(issuer)
                # basicConstraints CA:TRUE
                try:
                    bc = issuer.extensions.get_extension_for_oid(
                        ExtensionOID.BASIC_CONSTRAINTS)
                    if not bc.value.ca:
                        checks.append(("x", f"Issuer {issuer_cn} is NOT a CA (CA:FALSE)"))
                        self._errors.append((i, "issuer not a CA"))
                except x509.ExtensionNotFound:
                    checks.append(("!", f"Issuer {issuer_cn} has no basicConstraints"))
                    self._warnings.append((i, "issuer missing basicConstraints"))

                # keyUsage keyCertSign
                try:
                    ku = issuer.extensions.get_extension_for_oid(
                        ExtensionOID.KEY_USAGE)
                    if not ku.value.key_cert_sign:
                        checks.append(("x", f"Issuer {issuer_cn} lacks keyCertSign in X509v3 Key Usage"))
                        self._errors.append((i, "issuer lacks keyCertSign"))
                except x509.ExtensionNotFound:
                    pass  # keyUsage absence is not necessarily an error

            # --- pathLength enforcement (linked chain only) ---
            if is_linked and i + 1 < len(chain) and id(chain[i + 1]) in linked:
                self._check_pathlen(i, checks)

            # --- Self-signed root CA checks (end of linked chain) ---
            if is_self_signed and is_last_linked:
                try:
                    bc = cert.extensions.get_extension_for_oid(
                        ExtensionOID.BASIC_CONSTRAINTS)
                    if bc.value.ca:
                        checks.append(("+", "CA:TRUE"))
                    else:
                        checks.append(("!", "Self-signed but CA:FALSE"))
                        self._warnings.append((i, "self-signed but not CA"))
                except x509.ExtensionNotFound:
                    pass
                try:
                    ku = cert.extensions.get_extension_for_oid(
                        ExtensionOID.KEY_USAGE)
                    if ku.value.key_cert_sign:
                        checks.append(("+", "keyCertSign"))
                except x509.ExtensionNotFound:
                    pass

            self._status[i] = checks

    def _check_pathlen(self, child_idx: int, checks: list):
        """Check pathLength constraints for ancestors of cert at child_idx."""
        chain = self._ordered
        linked = self._linked_ids
        # For each ancestor in the linked chain, check pathLength
        for anc_idx in range(child_idx + 1, len(chain)):
            anc = chain[anc_idx]
            if id(anc) not in linked:
                continue
            try:
                bc = anc.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS)
                if bc.value.ca and bc.value.path_length is not None:
                    # Count CA certs between ancestor and child
                    ca_between = 0
                    for mid_idx in range(child_idx + 1, anc_idx):
                        mid = chain[mid_idx]
                        if id(mid) not in linked:
                            continue
                        try:
                            mbc = mid.extensions.get_extension_for_oid(
                                ExtensionOID.BASIC_CONSTRAINTS)
                            if mbc.value.ca:
                                ca_between += 1
                        except x509.ExtensionNotFound:
                            pass
                    if ca_between > bc.value.path_length:
                        anc_cn = self._cert_cn(anc)
                        checks.append(
                            ("x", f"pathLen violated: {anc_cn} allows "
                             f"{bc.value.path_length}, found {ca_between} CA(s) below"))
                        self._errors.append(
                            (child_idx, f"pathLength constraint violated at {anc_cn}"))
            except x509.ExtensionNotFound:
                pass

    # --- Single-cert handling ---------------------------------------------

    def _verify_single(self) -> dict:
        """Handle single certificate (trivial case)."""
        cert = self._certs[0]
        cn = self._cert_cn(cert)
        is_self_signed = (cert.subject.public_bytes() ==
                          cert.issuer.public_bytes())
        checks = []
        errors = 0
        warnings = 0

        # Validity
        if self._now < cert.not_valid_before_utc:
            checks.append(("x", f"NOT YET VALID (starts {format_dt(cert.not_valid_before_utc)})"))
            errors += 1
        elif self._now > cert.not_valid_after_utc:
            checks.append(("x", f"EXPIRED ({format_dt(cert.not_valid_after_utc)})"))
            errors += 1
        else:
            checks.append(("+", f"Valid (expires {format_dt(cert.not_valid_after_utc)})"))

        if is_self_signed:
            ok, msg = self._verify_sig(cert, cert)
            if ok is True:
                checks.append(("+", "Self-signed"))
            elif ok is None:
                checks.append(("!", f"Self-signed (signature not checked: {msg})"))
            else:
                checks.append(("x", "SELF-SIGNED SIGNATURE INVALID"))
                errors += 1
        else:
            checks.append(("!", "Issuer not in chain (single certificate)"))
            warnings += 1

        role = "self-signed" if is_self_signed else "leaf (no chain)"
        if errors == 0 and warnings == 0:
            result_str = "chain is internally consistent"
        elif errors == 0:
            result_str = f"chain has {warnings} warning(s)"
        elif warnings == 0:
            result_str = f"chain has {errors} error(s)"
        else:
            result_str = f"chain has {errors} error(s), {warnings} warning(s)"

        entry = {"index": 0, "cn": cn, "role": role, "checks": checks}
        error_certs = [entry] if any(s == "x" for s, _ in checks) else []
        warning_certs = [entry] if any(s == "!" for s, _ in checks) else []

        return {
            "ordered": [cert],
            "chain": [entry],
            "errors": errors,
            "warnings": warnings,
            "result": result_str,
            "error_certs": error_certs,
            "warning_certs": warning_certs,
            "by_cert": {id(cert): entry},
        }

    # --- Result formatting ------------------------------------------------

    def _build_result(self) -> dict:
        """Assemble final verification result."""
        chain_info = []
        linked = self._linked_ids
        for i, cert in enumerate(self._ordered):
            cn = self._cert_cn(cert)
            is_self_signed = (cert.subject.public_bytes() ==
                              cert.issuer.public_bytes())
            is_linked = id(cert) in linked

            if not is_linked:
                role = "self-signed root" if is_self_signed else "independent"
            elif i == 0 and not is_self_signed:
                role = "leaf"
            elif is_self_signed:
                role = "self-signed root"
            else:
                role = "intermediate"

            chain_info.append({
                "index": i,
                "cn": cn,
                "role": role,
                "checks": self._status.get(i, []),
            })

        n_err = len(self._errors)
        n_warn = len(self._warnings)
        if n_err == 0 and n_warn == 0:
            result_str = "chain is internally consistent"
        elif n_err == 0:
            result_str = f"chain has {n_warn} warning(s)"
        elif n_warn == 0:
            result_str = f"chain has {n_err} error(s)"
        else:
            result_str = f"chain has {n_err} error(s), {n_warn} warning(s)"

        # Error/warning summary: list certs that have errors or warnings
        error_certs = []
        warning_certs = []
        for entry in chain_info:
            errs = [(s, m) for s, m in entry["checks"] if s == "x"]
            warns = [(s, m) for s, m in entry["checks"] if s == "!"]
            if errs:
                error_certs.append(entry)
            if warns:
                warning_certs.append(entry)

        return {
            "ordered": self._ordered,
            "chain": chain_info,
            "errors": n_err,
            "warnings": n_warn,
            "result": result_str,
            "error_certs": error_certs,
            "warning_certs": warning_certs,
            # Lookup: id(cert) → chain entry (for inline per-cert display)
            "by_cert": {id(c): chain_info[i] for i, c in enumerate(self._ordered)
                        if i < len(chain_info)},
        }

    # --- Helpers ----------------------------------------------------------

    @staticmethod
    def _cert_cn(cert) -> str:
        dn = parse_dn(cert.subject)
        return dn.get("CN", "[no CN]")

    @staticmethod
    def _verify_sig(cert, issuer):
        """Verify *cert* was signed by *issuer*.

        Returns ``(True, None)`` on success, ``(False, msg)`` on failure,
        or ``(None, msg)`` when the signature algorithm is not supported
        by the cryptography library (e.g. SHA-1).
        """
        try:
            cert.verify_directly_issued_by(issuer)
            return True, None
        except Exception as e:
            msg = str(e)
            if "Unsupported" in msg or "unsupported" in msg:
                try:
                    alg = cert.signature_hash_algorithm.name.upper()
                except Exception:
                    alg = "unknown"
                return None, f"deprecated algorithm: {alg}"
            return False, msg                         # genuine failure


def format_chain_header(vresult: dict) -> str:
    """Format chain verification header line."""
    n = len(vresult.get("ordered", []))
    return f"  # Chain verification: {n} certificate(s)"


def format_chain_cert_checks(vresult: dict, cert, display_idx: int = None) -> str:
    """Format inline verification checks for a single certificate."""
    entry = vresult.get("by_cert", {}).get(id(cert))
    if not entry:
        return ""
    role = entry["role"]
    checks = entry["checks"]
    idx = display_idx if display_idx is not None else entry["index"]
    lines = [f"        # - chain: [{idx}] {entry['cn']}  ← {role}"]
    for symbol, msg in checks:
        lines.append(f"        #         {symbol} {msg}")
    return "\n".join(lines)


def format_chain_result(vresult: dict, chain_to_display: dict = None) -> str:
    """Format chain verification result line with error/warning summary."""
    result = vresult["result"]
    lines = [f"  # Chain verification result: {result}"]

    for entry in vresult.get("error_certs", []):
        errs = [m for s, m in entry["checks"] if s == "x"]
        didx = (chain_to_display or {}).get(entry["index"], entry["index"])
        lines.append("")
        lines.append(f"  # - chain: [{didx}] {entry['cn']}  ← {entry['role']}")
        for e in errs:
            lines.append(f"  #         x {e}")

    for entry in vresult.get("warning_certs", []):
        warns = [m for s, m in entry["checks"] if s == "!"]
        didx = (chain_to_display or {}).get(entry["index"], entry["index"])
        lines.append("")
        lines.append(f"  # - chain: [{didx}] {entry['cn']}  ← {entry['role']}")
        for w in warns:
            lines.append(f"  #         ! {w}")

    return "\n".join(lines)


def format_chain_verification(vresult: dict) -> str:
    """Format chain verification result as comment block for CLI output (legacy)."""
    lines = ["  # Chain verification:"]
    for entry in vresult["chain"]:
        idx = entry["index"]
        cn = entry["cn"]
        role = entry["role"]
        lines.append(f"  #   [{idx}] {cn}  ← {role}")
        for symbol, msg in entry["checks"]:
            lines.append(f"  #         {symbol} {msg}")
    result = vresult["result"]
    lines.append(f"  #   Result: {result}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
#  Weakness Scanner — config-driven cryptographic weakness detection
# ---------------------------------------------------------------------------

class WeaknessScanner:
    """Scan X.509 certificates for cryptographic weaknesses.

    Checks are driven by a config file (configs/weak.conf) rather than
    hardcoded rules, so policies can be customized per deployment.

    Supported rule categories:
      - key    <type>:<max_bits>   — key too small (RSA, EC, DSA)
      - sig    <algorithm>         — weak signature hash algorithm
      - validity  days:<max_days>  — certificate lifetime too long
    """

    def __init__(self, certs: list, config_paths: list = None):
        """Initialize with certificates and optional config file paths.

        Args:
            certs: list of x509.Certificate objects to scan.
            config_paths: list of config file paths to load.
                If None, loads default configs/weak.conf from script directory.
                If an explicit list (even empty), ONLY those files are loaded
                — the default is not auto-added.  This allows focused scans.
        """
        self._certs = list(certs)
        self._rules = []           # list of (severity, category, pattern, description)
        self._status = {}          # cert id → list of (symbol, message)
        self._errors = []          # (index, message) for x findings
        self._warnings = []        # (index, message) for ! findings

        if config_paths is not None:
            # Explicit list — use exactly these files, no auto-default
            self._config_paths = list(config_paths)
        else:
            # No paths given — load default config relative to script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            default_conf = os.path.join(script_dir, "..", "configs", "weak.conf")
            if os.path.isfile(default_conf):
                self._config_paths = [default_conf]
            else:
                self._config_paths = []

    def scan(self) -> dict:
        """Run weakness scan and return structured result.

        Returns dict with:
            certs:    list of per-cert dicts with cn, checks, index
            by_cert:  dict mapping cert id(cert) → entry dict
            errors:   int — total weakness count (x findings)
            warnings: int — total advisory count (! findings)
            rules:    int — number of active rules
            result:   str — summary line
            error_certs:   list of entries with x findings
            warning_certs: list of entries with ! findings (no x)
        """
        self._load_config()

        if not self._rules:
            return {"certs": [], "by_cert": {}, "errors": 0,
                    "warnings": 0, "rules": 0,
                    "config_files": list(self._config_paths),
                    "result": "no weakness rules loaded",
                    "error_certs": [], "warning_certs": []}

        entries = []
        by_cert = {}
        for i, cert in enumerate(self._certs):
            checks = self._check_cert(cert, i)
            cn = _cert_cn(cert)
            entry = {"index": i, "cn": cn, "checks": checks}
            entries.append(entry)
            by_cert[id(cert)] = entry

        # Collect error/warning certs
        error_certs = [e for e in entries if any(s == "x" for s, _ in e["checks"])]
        warning_only = [e for e in entries
                        if any(s == "!" for s, _ in e["checks"])
                        and not any(s == "x" for s, _ in e["checks"])]

        nerr = sum(1 for e in entries for s, _ in e["checks"] if s == "x")
        nwarn = sum(1 for e in entries for s, _ in e["checks"] if s == "!")

        if nerr == 0 and nwarn == 0:
            result_str = "no weaknesses found"
        elif nerr == 0:
            result_str = f"{nwarn} advisory(s)"
        elif nwarn == 0:
            result_str = f"{nerr} weakness(es)"
        else:
            result_str = f"{nerr} weakness(es), {nwarn} advisory(s)"

        return {
            "certs": entries,
            "by_cert": by_cert,
            "errors": nerr,
            "warnings": nwarn,
            "rules": len(self._rules),
            "config_files": list(self._config_paths),
            "result": result_str,
            "error_certs": error_certs,
            "warning_certs": warning_only,
        }

    def _load_config(self):
        """Parse all config files into rules list."""
        seen_files = set()
        for path in self._config_paths:
            rpath = os.path.realpath(path)
            if rpath in seen_files:
                continue
            seen_files.add(rpath)
            try:
                with open(path, "r") as f:
                    for line_no, raw in enumerate(f, 1):
                        line = raw.split("#", 1)[0].strip()  # strip inline comments
                        if not line:
                            continue
                        parts = line.split(None, 3)
                        if len(parts) < 3:
                            continue  # malformed line
                        severity = parts[0]
                        if severity not in ("x", "!"):
                            continue  # unknown severity
                        category = parts[1].lower()
                        pattern = parts[2]
                        desc = parts[3] if len(parts) > 3 else pattern
                        self._rules.append((severity, category, pattern, desc))
            except (IOError, OSError):
                pass  # config file not found — silently skip

    def _check_cert(self, cert, idx: int) -> list:
        """Check one certificate against all rules. Returns list of (symbol, message)."""
        checks = []

        # Extract cert properties once
        key_type, key_size = self._extract_key_info(cert)
        sig_hash = self._extract_sig_info(cert)
        lifetime_days = self._extract_validity(cert)

        for severity, category, pattern, desc in self._rules:
            match = False

            if category == "key":
                # Pattern: TYPE:MAX_BITS  e.g. RSA:1024
                try:
                    rule_type, rule_max = pattern.split(":", 1)
                    rule_max = int(rule_max)
                    if key_type and key_type.upper() == rule_type.upper():
                        if key_size <= rule_max:
                            match = True
                except (ValueError, AttributeError):
                    pass

            elif category == "sig":
                # Pattern: algorithm name  e.g. sha1, md5
                if sig_hash and sig_hash.lower() == pattern.lower():
                    match = True

            elif category == "validity":
                # Pattern: days:MAX_DAYS  e.g. days:398
                try:
                    _, max_days = pattern.split(":", 1)
                    max_days = int(max_days)
                    if lifetime_days is not None and lifetime_days > max_days:
                        match = True
                except (ValueError, AttributeError):
                    pass

            if match:
                checks.append((severity, desc))
                if severity == "x":
                    self._errors.append((idx, desc))
                else:
                    self._warnings.append((idx, desc))

        return checks

    @staticmethod
    def _extract_key_info(cert) -> tuple:
        """Extract key type name and size from certificate. Returns (type_str, size_int)."""
        try:
            key = cert.public_key()
        except Exception:
            return None, 0

        if isinstance(key, rsa.RSAPublicKey):
            return "RSA", key.key_size
        if isinstance(key, ec.EllipticCurvePublicKey):
            return "EC", key.key_size
        if isinstance(key, dsa.DSAPublicKey):
            return "DSA", key.key_size
        if isinstance(key, ed25519.Ed25519PublicKey):
            return "Ed25519", 256
        if isinstance(key, ed448.Ed448PublicKey):
            return "Ed448", 448

        # PQC or unknown
        return None, 0

    @staticmethod
    def _extract_sig_info(cert) -> str:
        """Extract signature hash algorithm name. Returns lowercase string or None."""
        try:
            alg = cert.signature_hash_algorithm
            if alg is not None:
                return alg.name.lower()
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_validity(cert) -> int:
        """Extract certificate lifetime in days. Returns int or None."""
        try:
            nb = cert.not_valid_before_utc
            na = cert.not_valid_after_utc
            return (na - nb).days
        except Exception:
            return None


def _cert_cn(cert) -> str:
    """Extract CN from certificate subject, or fall back to first RDN."""
    try:
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cns:
            return cns[0].value
    except Exception:
        pass
    try:
        return cert.subject.rfc4514_string()[:60]
    except Exception:
        return "(unknown)"


# --- Weakness scan formatting (parallel to chain verification) ---

def format_weak_header(wresult: dict, ncerts: int = None) -> str:
    """Format weakness scan header line."""
    n = ncerts if ncerts is not None else len(wresult.get("certs", []))
    r = wresult.get("rules", 0)
    conf_names = [os.path.basename(p) for p in wresult.get("config_files", [])]
    conf_str = ", ".join(conf_names) if conf_names else "none"
    return f"  # Weakness scan: {n} certificate(s), {r} rule(s) from {conf_str}"


def format_weak_cert_checks(wresult: dict, cert, display_idx: int = None) -> str:
    """Format inline weakness checks for a single certificate."""
    entry = wresult.get("by_cert", {}).get(id(cert))
    if not entry:
        return ""
    idx = display_idx if display_idx is not None else entry["index"]
    cn = entry["cn"]
    checks = entry["checks"]
    if not checks:
        return f"        # - weak:  [{idx}] {cn}\n        #         + no weaknesses found"
    lines = [f"        # - weak:  [{idx}] {cn}"]
    for symbol, msg in checks:
        lines.append(f"        #         {symbol} {msg}")
    return "\n".join(lines)


def format_weak_result(wresult: dict, chain_to_display: dict = None) -> str:
    """Format weakness scan result line with error/advisory summary."""
    result = wresult["result"]
    lines = [f"  # Weakness scan result: {result}"]

    for entry in wresult.get("error_certs", []):
        errs = [m for s, m in entry["checks"] if s == "x"]
        didx = (chain_to_display or {}).get(entry["index"], entry["index"])
        lines.append("")
        lines.append(f"  # - weak:  [{didx}] {entry['cn']}")
        for e in errs:
            lines.append(f"  #         x {e}")

    for entry in wresult.get("warning_certs", []):
        warns = [m for s, m in entry["checks"] if s == "!"]
        didx = (chain_to_display or {}).get(entry["index"], entry["index"])
        lines.append("")
        lines.append(f"  # - weak:  [{didx}] {entry['cn']}")
        for w in warns:
            lines.append(f"  #         ! {w}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
#  Help / Version text builders
# ---------------------------------------------------------------------------

def _help_text() -> str:
    return f"""cert-grep.py v{__version__}

Usage:
  $ cert-grep.py  <cert_file>  [options...]
  $ cert-grep.py  <file1> <file2> ... [options...]
  $ cat <cert_file> | cert-grep.py -  [options...]

Library usage:
  from cert_grep import cert_grep
  text = cert_grep("cert.pem", level=2, show_pub=True)
  text = cert_grep("bundle.p12", password="secret")
  text = cert_grep(<cert_file> or "-", level=0)
  text = cert_grep("--version", output=None)

Options (case-insensitive, order-independent):
  0 | summary_0      Short: Issuer CN, Subject CN, Serial, Validity
  1 | summary_1      Default: Algorithms, DN breakdown, Validity, Key extensions
  2 | summary_2      Verbose: All extensions + fingerprints
  3 | summary_3      Near-full: Full text, hex lines stripped
  4 | full           Full OpenSSL-style text output

  pem                 Assume PEM format, skip auto-detect
  der                 Assume DER format
  x509                Assume X.509 type format
  p7 | pkcs7          Assume PKCS#7 type format
  csr                 Assume CSR (PKCS#10) type format
  crl                 Assume CRL type format
  key                 Assume private key type format
  pubkey              Assume public key type format
  p12 | pkcs12 | pfx  Assume PKCS#12 container format
  jks | jceks         Assume Java KeyStore format
  b64                 Assume base64 format

  pub               Show public key details (RSA/ECC/EdDSA)
  fp                Show fingerprints (MD5, SHA-1, SHA-256)
  ver               Verify certificate chain (2+ certs)
  weak              Scan for cryptographic weaknesses (policy-driven)
  file              Save decoded certificate in current directory
  c0                Show only the first certificate (cert 0)
  cN                Show only item N (e.g. c0, c1, c42)

  -v, --verbose     Verbose diagnostics (stacks: -v -v for more)
  -V, --version     Show version and exit
  -h, --help        Show this help

  PW=<password>     Supply passphrase for encrypted keys / PKCS#12
  PW=prompt         Prompt interactively for the passphrase
  PW=env:<VAR>      Read passphrase from environment variable
  PW=file:<path>    Read passphrase from file
                    Single-line:  use as password (backward compatible)
                    Multi-line:   password file with glob→password mappings

  Per-file passwords (multi-file mode):
  <file>:PW=<password>    Per-file passphrase (overrides shared PW=)
  <file>:PW=file:<path>   Per-file passphrase from file
  <file>:PW=env:<VAR>     Per-file passphrase from env var

  WEAK=<path>       Load additional weakness policy file(s)
                    (comma-separated, globs supported)
                    Default: configs/weak.conf (relative to the top level of the distribution)

Environment variables:
  $CERTGREP_SUMMARY   Default summary level: 0-4 or full (overridden by CLI arg)
  $CERTGREP_CNUM      Default cert index: 0=c0, N=cN (overridden by CLI arg)
  $CERTGREP_FP=yes    Enable fingerprints (overridden by CLI arg)
  $CERTGREP_PUB=yes   Enable public key details (overridden by CLI arg)
  $VERBOSE            Verbosity: 0-2, equivalent to -v / -v -v

Examples:
  $ cert-grep.py cert-example.pem
  $ cert-grep.py cert-example.pem summary_0
  $ cert-grep.py cert-example.pem summary_2 pub fp
  $ cert-grep.py cert-example.der DER
  $ cert-grep.py cert-example.p7b
  $ cert-grep.py cert-example.b64

  $ cert-grep.py fullchain.pem ver              # - verify certificate chain
  $ cert-grep.py fullchain.pem weak             # - scan for weaknesses
  $ cert-grep.py fullchain.pem ver weak         # - both: verify + weakness scan
  $ cert-grep.py cert.pem WEAK=quantum.conf     # - custom weakness policy
  $ cat cert.pem | cert-grep.py - summary_0
  $ cert-grep.py device.csr                   # - CSR auto-detected
  $ cert-grep.py device.csr.der DER           # - CSR in DER format
  $ cat device.csr | cert-grep.py - csr       # - CSR from stdin
  $ cert-grep.py ca.crl                       # - CRL auto-detected
  $ cert-grep.py ca.crl summary_2             # - CRL with revoked entries
  $ cert-grep.py server-key.pem               # - private key auto-detected
  $ cert-grep.py server-key.pem pub           # - with public key details
  $ cert-grep.py mykey.pem key                # - force key type detection
  $ cert-grep.py bundle.p12                   # - PKCS#12 auto-detected
  $ cert-grep.py bundle.pfx summary_2 fp      # - PKCS#12 verbose + fingerprints
  $ cert-grep.py bundle.p12 PW=mysecret       # - PKCS#12 with password
  $ cert-grep.py bundle.p12 PW=prompt         # - interactive password prompt
  $ cert-grep.py bundle.p12 PW=env:P12_PASS   # - password from env var
  $ cert-grep.py bundle.p12 PW=file:/tmp/pw   # - password from file
  $ cert-grep.py encrypted-key.pem PW=secret  # - decrypt private key

Multi-file mode:
  $ cert-grep.py *.pem                        # - all PEM files in directory
  $ cert-grep.py cert.pem key.pem ca.crl      # - mixed types
  $ cert-grep.py *.pem summary_0 weak         # - batch audit
  $ cert-grep.py *.p12 PW=changeit            # - shared password
  $ cert-grep.py a.p12:PW=secret1 b.p12:PW=secret2   # - per-file passwords
  $ cert-grep.py a.jks:PW=changeit b.p12:PW=mypass   # - mixed formats
  $ cert-grep.py *.p12 PW=file:passwords.txt  # - password file (batch)

JSON / REST API:
  $ curl https://vault.example.com/v1/pki/cert/ca | cert-grep.py -
                                              # - Vault / REST API JSON (PEM auto-unwrapped)
  $ kubectl get CertificateRequest/NAME -o json | jq '.spec.request' | cert-grep.py -
                                              # - pre-filtered field (jq quotes auto-stripped)

Kubernetes / cert-manager:
  $ kubectl get CertificateRequest/NAME -o json | cert-grep.py -
                                              # - full resource: CSR + cert + CA extracted
  $ kubectl get secret/NAME -o json | cert-grep.py -
                                              # - TLS Secret: tls.crt + tls.key extracted
  $ kubectl get CertificateRequest -o json | cert-grep.py -
                                              # - List: all requests in namespace

Password file format (PW=file:<path> with multi-line file):
  A multi-line password file maps file patterns to passwords for batch
  processing of many encrypted containers with different passwords.

    # Comments and blank lines are ignored.
    # Mapped: <glob-pattern> <whitespace> <password>
    *.Cretins-4us.p12    Cretins-4us
    *.Lame.p12           Lame
    server-*.jks         S3cret With Spaces
    weird-app.p12        ' begins-with-space'   # quoted: leading space

    # Defaults (bare lines): tried in order for unmatched files.
    changeit
    mypass99
    'a default with spaces'

  Parsing: pattern is everything before the first whitespace; password is
  everything after.  Outer single/double quotes are stripped from passwords.
  A line with no whitespace is a default password.  Glob matching is on
  basename only (fnmatch).  First matching pattern wins; defaults are tried
  in file order.  A single-line file is backward-compatible (plain password).

Private key summary:
  Private keys are auto-detected by PEM markers or filename (*-key*, *.key).
  Only safe metadata is shown: type, size, curve, PEM format, encryption status,
  and public key fingerprint (for matching to certificates).
  No private key material is ever displayed.
  Encrypted keys are detected but cannot be inspected without the passphrase.
  Use PW=<password> to decrypt and inspect encrypted keys.

PKCS#12 containers (.p12, .pfx):
  PKCS#12 files are auto-detected by filename (.p12, .pfx) or binary content.
  All components are shown: certificate(s), CA chain, and private key summary.
  The private key summary follows the same safe-metadata rules as standalone keys.
  Password-protected PKCS#12 files require PW=<password> to inspect.
  Without a password, a graceful "password required" message is shown.
  Use 'file' to save the certificate(s) as PEM (key is not saved).

Java KeyStores (.jks, .jceks):
  JKS/JCEKS files are auto-detected by filename (.jks, .jceks) or magic bytes.
  Entry types: trustedCertEntry, privateKeyEntry, secretKeyEntry (JCEKS).
  All entry aliases are shown. Certificates and private keys use the same
  formatters as standalone files; secret keys show algorithm and size.
  Default password 'changeit' is tried automatically (Java convention).
  Requires the 'pyjks' library: pip install pyjks

FYI:
  Post-Quantum Cryptography (ML-DSA, ML-KEM, SLH-DSA) certificates are detected
    and displayed, but full PQC key decoding requires pyca/cryptography PQC support.
    Tracking: https://github.com/pyca/cryptography/issues/12610
  Hybrid certificate extensions (2.5.29.72/73/74) are recognized and decoded.

See also:
  Source:     https://gitlab.com/umi-ch/cert-grep
  Web UI:     https://gitlab.com/umi-ch/cert-grep (web/ directory)
  Test data:  https://gitlab.com/umi-ch/bashrc/-/tree/main/zPKI
  Library:    https://pypi.org/project/cryptography
              https://cryptography.io/en/latest
"""


def _version_text() -> str:
    from cryptography.hazmat.backends.openssl import backend as ossl_backend
    return (
        f"\n  cert-grep.py:      v{__version__}\n"
        f"  cryptography:      {crypto_version}\n"
        f"  internal openssl:  {ossl_backend.openssl_version_text()} "
        f"(0x{ossl_backend.openssl_version_number():x})\n"
    )


# ---------------------------------------------------------------------------
#  Library entry point
# ---------------------------------------------------------------------------

_LEVEL_MAP = {
    0: "summary_0", 1: "summary_1", 2: "summary_2",
    3: "summary_3", 4: "summary_4",
    "0": "summary_0", "1": "summary_1", "2": "summary_2",
    "3": "summary_3", "4": "summary_4",
    "summary_0": "summary_0", "summary_1": "summary_1",
    "summary_2": "summary_2", "summary_3": "summary_3",
    "summary_4": "summary_4", "full": "summary_4",
}


def _filter_cert_index(text: str, index: int) -> str:
    """Return only the certificate at the given index from formatted output.

    Each cert block consists of:
      1. optional chain-check comment lines (``# - chain: [N] ...``)
      2. optional weakness-check comment lines (``# - weak:  [N] ...``)
      3. the ``N: Certificate:`` (or ``N: CSR:``) header
      4. the cert/csr body lines

    Also includes the chain/weakness scan headers and result footers.
    """
    lines = text.split("\n")
    max_idx = -1
    for line in lines:
        m = re.match(r"(\d+):\s", line)
        if m:
            max_idx = max(max_idx, int(m.group(1)))

    # Regex for annotation block starts (chain or weak)
    _block_re = re.compile(r"\s*# - (?:chain|weak):\s*\[")
    # Regex for footer starts
    _footer_re = re.compile(r"\s*# (?:Chain verification|Weakness scan) result:")
    # Regex for footer entry lines
    _footer_entry_re = re.compile(r"\s*# - (?:chain|weak):\s*\[(\d+)\]")

    out = []
    check_buf = []          # buffer for "# - chain/weak:" block + trailing blanks
    collecting = False      # True while inside the target cert body
    in_footer = False       # True once we hit a result footer
    in_preamble = True      # True until first check block or "N:" line
    target_prefix = f"{index}:"

    for line in lines:
        # --- preamble: preserve all lines before first chain/weak/cert content ---
        if in_preamble:
            if _block_re.match(line) or re.match(r"\d+:\s", line):
                in_preamble = False
                # fall through to normal processing
            else:
                out.append(line)
                continue

    for line in lines:
        # --- footer: include result line, but filter error entries ---
        if _footer_re.match(line):
            collecting = False
            in_footer = True
            footer_match = False
            out.append(line)
            continue
        if in_footer:
            # Start of a "# - chain: [N]" or "# - weak:  [N]" entry
            m_entry = _footer_entry_re.match(line)
            if m_entry:
                footer_match = (int(m_entry.group(1)) == index)
            if footer_match or (not m_entry and not re.match(r"\s*#\s", line)):
                # Include matching entries and non-comment lines (trailing blank)
                out.append(line)
            elif not m_entry and not footer_match:
                # Detail line for a non-matching entry — skip
                pass
            continue

        # --- check block: buffer until we know which cert it's for ---
        if _block_re.match(line):
            if collecting:
                # Hit the next cert's check block — done collecting
                collecting = False
                check_buf = [line]
                continue
            check_buf = [line]
            continue

        # Continuation of check block (indented "# " lines or blanks)
        if check_buf and not collecting:
            if re.match(r"\s*#\s", line):
                check_buf.append(line)
                continue
            if line.strip() == "":
                check_buf.append(line)
                continue
            # Non-comment, non-blank line: check if it's our target
            if line.startswith(target_prefix):
                out.extend(check_buf)
                check_buf = []
                collecting = True
                out.append(line)
                continue
            else:
                check_buf = []
                # fall through to normal processing

        # --- cert header ---
        if line.startswith(target_prefix) and not collecting:
            collecting = True
            out.append(line)
            continue

        # Another cert's header — stop
        if collecting and re.match(r"\d+:\s", line):
            collecting = False
            continue

        if collecting:
            out.append(line)

    if not out or all(l.strip() == "" for l in out):
        total = max_idx + 1 if max_idx >= 0 else 0
        return f"{max_idx} + 1 = {total} items in file (last index: {max_idx})"
    return "\n".join(out)


def cert_grep(
    source,                     # str/Path (filename), bytes (raw cert/csr data),
                                #   or "-" (stdin), "--help", "-h", "--version", "-V"
    level=1,                    # 0-4, or "summary_0".."summary_4", or "full"
    verbose=0,                  # 0=quiet, 1+=diagnostics (stacks with $VERBOSE env)
    show_pub=False,             # show public key details
    show_fp=False,              # show fingerprints (MD5, SHA-1, SHA-256)
    save_file=False,            # save decoded cert(s)/csr(s) as PEM to current directory
    force_type=None,            # "x509" | "pkcs7" | "csr" — override auto-detection
    force_encoding=None,        # "pem" | "der"    — override auto-detection
    force_b64=False,            # force base64 decode before parsing
    first_only=False,           # show only the first cert (like f_zero)
    cert_index=None,            # show only cert N (int), e.g. cert_index=0 same as first_only
    password=None,              # str/bytes/None — passphrase for encrypted keys / PKCS#12
    verify_chain=False,       # run chain verification (2+ certs)
    weakness_scan=False,      # run weakness scan against policy config
    weak_configs=None,        # list of additional weak.conf paths (or None)
    output=sys.stdout,          # file-like to print to, or None = return only
) -> str:
    """Inspect X.509 / PKCS#7 certificates, PKCS#10 CSRs, CRLs, PKCS#12 containers, or private keys.

    Returns formatted text. Private key summaries show only safe metadata
    (type, size, curve, format) — no private material is ever exposed.

    Args:
        source:  Filename (str/Path), raw certificate/CSR/CRL/key/PKCS#12 bytes, "-" for stdin,
                 or "--help"/"-h"/"--version"/"-V" for informational output.
        level:   Summary level 0-4 (int) or name ("summary_0".."full").
        verbose: Verbosity (0=normal, 1+=diagnostics). Stacks with $VERBOSE env.
        show_pub:  Include public key details (RSA modulus, EC params, etc.).
        show_fp:   Include MD5/SHA-1/SHA-256 fingerprints.
        save_file: Write each cert/CSR/CRL as cert_grep_output_N.pem in cwd.
                   Disabled for private keys (security).
        force_type:     Override format auto-detection: "x509", "pkcs7", "csr",
                        "crl", "key", "pubkey", or "pkcs12".
        force_encoding: Override encoding auto-detection: "pem" or "der".
        force_b64:      Force base64 decoding of input before parsing.
        first_only:     Show only the first certificate (cert 0), like f_zero.
        cert_index:     Show only item N (0-based).  Overrides first_only.
        password:  Passphrase for encrypted keys or PKCS#12 containers (str, bytes, or None).
                   If None: encrypted keys show metadata only; encrypted PKCS#12 reports
                   "password required". If incorrect: raises ValueError.
        verify_chain: Run chain verification on 2+ certificates (PEM chains, PKCS#12).
        weakness_scan: Run weakness scan against config policy (configs/weak.conf).
        weak_configs:  List of additional config file paths for weakness rules,
                       or None. Default configs/weak.conf is always loaded.
        output:  File-like object for printed output (default: sys.stdout).
                 Pass None to suppress printing; the text is still returned.

    Returns:
        The formatted certificate/CSR/CRL/key/PKCS#12 text as a string.

    Raises:
        FileNotFoundError: If source is a filename that doesn't exist.
        ValueError:        If the certificate/CSR/CRL/key/PKCS#12 data cannot be parsed,
                           or the password is incorrect.
    """
    lines = []   # collect all output lines

    def _print(msg=""):
        lines.append(msg)

    # -- Handle informational requests --
    if isinstance(source, str) and source in ("--help", "-h"):
        text = _help_text()
        if output is not None:
            print(text, file=output)
        return text

    if isinstance(source, str) and source in ("--version", "-V"):
        text = _version_text()
        if output is not None:
            print(text, file=output)
        return text

    # -- Resolve level --
    lvl = _LEVEL_MAP.get(level)
    if lvl is None:
        raise ValueError(f"Invalid level: {level!r}  (use 0-4 or 'summary_0'..'full')")

    # summary_2 and summary_3 implicitly enable fingerprints
    if lvl in ("summary_2", "summary_3"):
        show_fp = True

    # -- Normalize password --
    pw_bytes = _normalize_password(password)

    # -- Read input --
    if isinstance(source, bytes):
        data = source
        filename = "<bytes>"
    elif isinstance(source, (str, Path)) and str(source) == "-":
        data = sys.stdin.buffer.read()
        filename = "<stdin>"
    elif isinstance(source, (str, Path)):
        p = Path(source)
        if not p.exists():
            raise FileNotFoundError(f"can't read file: {source}")
        data = p.read_bytes()
        filename = str(source)
    else:
        raise TypeError(f"source must be str, Path, or bytes, not {type(source).__name__}")

    # -- Kubernetes / REST JSON extraction --
    # Must run before detect_format() so JSON is handled before DER/PEM sniffing.
    # Recursive calls are safe: extracted bytes are DER or PEM, never JSON again.
    k8s_items = _try_k8s_json_extract(data)
    if k8s_items is not None:
        _print(f"-> JSON: {len(k8s_items)} PKI object(s) extracted")
        _print()
        collected = []
        for label, item_bytes in k8s_items:
            _print(f"# {label}:")
            item_text = cert_grep(
                source=item_bytes,
                level=level, verbose=verbose,
                show_pub=show_pub, show_fp=show_fp,
                password=password,
                first_only=first_only,
                cert_index=cert_index,
                verify_chain=False,   # cross-item chain/weak deferred to future
                weakness_scan=False,
                output=None,
            )
            # Re-indent item output slightly so header stands out
            for line in item_text.splitlines():
                _print(line)
            _print()
            collected.append(item_text)
        text = "\n".join(lines)
        if output is not None:
            print(text, file=output)
        return text

    # -- Detect format --
    fmt = detect_format(data, filename)

    if force_type:     fmt["type"]     = force_type
    if force_encoding: fmt["encoding"] = force_encoding
    if force_b64 and not fmt["was_b64"]:
        decoded = try_b64_decode(data)
        if decoded:
            fmt["data"] = decoded
            fmt["was_b64"] = True

    if fmt["was_b64"] and verbose >= 1:
        _print("-> Base64 decode")

    if fmt["was_json"] and verbose >= 1:
        _print("-> JSON-unwrapped PEM")

    # -- Load and format --
    _save_certs = None    # set when save_file + x509 certs
    _save_has_key = False
    if fmt["type"] == "pkcs12":
        # PKCS#12 container (.p12 / .pfx)
        p12 = load_pkcs12(fmt["data"], fmt, password=pw_bytes)
        if verbose >= 1:
            n_certs = (1 if p12["cert"] else 0) + len(p12["chain"])
            _print(f"  # PKCS#12 container: {n_certs} certificate(s)"
                   f", {'1 key' if p12['key'] else 'no key'}")
            _print(f"  # Format: {fmt['type']}/{fmt['encoding']}"
                   + (f"  (was base64)" if fmt["was_b64"] else "")
                   + (f"  (was JSON)" if fmt["was_json"] else ""))

        _print()
        _print("PKCS#12 Container:")

        if p12["encrypted"]:
            # Password-protected and no (correct) password was supplied
            _print("  *** Password-protected PKCS#12 — cannot inspect without passphrase ***")
            _print("  Hint: use PW=<password> to supply the passphrase.")
        else:
            # --- Certificates ---
            cert_idx = 0
            cert_formatter = CertFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
            all_p12_certs = ([p12["cert"]] if p12["cert"] else []) + p12["chain"]

            # Run chain verification first (if requested)
            vresult = None
            if verify_chain and len(all_p12_certs) >= 2:
                verifier = ChainVerifier(all_p12_certs)
                vresult = verifier.verify()
                if verbose >= 1:
                    _print("  #")
                else:
                    _print()
                _print(format_chain_header(vresult))

            # Run weakness scan (if requested)
            wresult = None
            if weakness_scan and all_p12_certs:
                scanner = WeaknessScanner(all_p12_certs, config_paths=weak_configs)
                wresult = scanner.scan()
                if not vresult:
                    if verbose >= 1:
                        _print("  #")
                    else:
                        _print()
                _print(format_weak_header(wresult, ncerts=len(all_p12_certs)))

            if p12["cert"]:
                _print()
                if vresult:
                    checks = format_chain_cert_checks(vresult, p12["cert"], display_idx=cert_idx)
                    if checks:
                        _print()
                        _print(checks)
                        _print()
                if wresult and wresult["rules"] > 0:
                    wchecks = format_weak_cert_checks(wresult, p12["cert"], display_idx=cert_idx)
                    if wchecks:
                        if not vresult:
                            _print()
                        _print(wchecks)
                        _print()
                _print(cert_formatter.format(p12["cert"], cert_idx, lvl))
                cert_idx += 1
            for ca_cert in p12["chain"]:
                _print()
                if vresult:
                    checks = format_chain_cert_checks(vresult, ca_cert, display_idx=cert_idx)
                    if checks:
                        _print()
                        _print(checks)
                        _print()
                if wresult and wresult["rules"] > 0:
                    wchecks = format_weak_cert_checks(wresult, ca_cert, display_idx=cert_idx)
                    if wchecks:
                        if not vresult:
                            _print()
                        _print(wchecks)
                        _print()
                _print(cert_formatter.format(ca_cert, cert_idx, lvl))
                cert_idx += 1

            if vresult:
                by_cert = vresult.get("by_cert", {})
                chain_to_display = {}
                for didx, c in enumerate(all_p12_certs):
                    entry = by_cert.get(id(c))
                    if entry:
                        chain_to_display[entry["index"]] = didx
                _print()
                _print()
                _print(format_chain_result(vresult, chain_to_display))

            if wresult and wresult["rules"] > 0:
                weak_to_display = {i: i for i in range(len(all_p12_certs))}
                if not vresult:
                    _print()
                _print()
                _print(format_weak_result(wresult, weak_to_display))

            # --- Private key ---
            if p12["key"]:
                key_formatter = KeyFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
                _print()
                _print(key_formatter.format(p12["key"], 0, lvl))

            if not p12["cert"] and not p12["chain"] and not p12["key"]:
                _print("  (empty container)")

            if save_file:
                _print()
                save_idx = 0
                if p12["cert"]:
                    out_name = f"cert_grep_output_{save_idx}.pem"
                    with open(out_name, "wb") as f:
                        f.write(p12["cert"].public_bytes(serialization.Encoding.PEM))
                    _print(f"-> Certificate:  {os.path.abspath(out_name)}")
                    save_idx += 1
                for ca_cert in p12["chain"]:
                    out_name = f"cert_grep_output_{save_idx}.pem"
                    with open(out_name, "wb") as f:
                        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
                    _print(f"-> CA Certificate:  {os.path.abspath(out_name)}")
                    save_idx += 1
                if p12["key"]:
                    _print("-> Note: private key not saved (security).")

    elif fmt["type"] == "jks":
        # Java KeyStore (.jks / .jceks)
        try:
            jks_data = load_jks(fmt["data"], fmt, password=pw_bytes)
        except ValueError as e:
            if "Incorrect password" in str(e):
                # Wrong password — show specific error, not generic locked
                jks_data = {"entries": [], "encrypted": True,
                            "store_type": fmt.get("jks_subtype", "jks"),
                            "password_used": None,
                            "bad_password": True}
            else:
                raise
        store_type = jks_data["store_type"].upper()
        if verbose >= 1:
            n_trusted = sum(1 for e in jks_data["entries"] if e["type"] == "trusted_cert")
            n_privkey = sum(1 for e in jks_data["entries"] if e["type"] == "private_key")
            n_secret  = sum(1 for e in jks_data["entries"] if e["type"] == "secret_key")
            parts = []
            if n_trusted: parts.append(f"{n_trusted} trusted cert(s)")
            if n_privkey: parts.append(f"{n_privkey} private key(s)")
            if n_secret:  parts.append(f"{n_secret} secret key(s)")
            _print(f"  # {store_type} container: {', '.join(parts) or 'empty'}")
            _print(f"  # Format: {fmt['type']}/{fmt['encoding']}"
                   + (f"  (was base64)" if fmt["was_b64"] else "")
                   + (f"  (was JSON)" if fmt["was_json"] else ""))
            pw_used = jks_data.get("password_used")
            if pw_used == "changeit":
                _print(f"  # Guessing default JKS NOOP password: 'changeit'")

        _print()
        _print(f"{store_type} KeyStore:")

        if jks_data.get("bad_password"):
            _print(f"  *** Incorrect password for {store_type} KeyStore ***")
            _print("  Hint: use PW=<password> to supply the correct passphrase.")
        elif jks_data["encrypted"]:
            _print(f"  *** Password-protected {store_type} — cannot inspect without passphrase ***")
            _print("  Hint: use PW=<password> to supply the passphrase.")
            _print("  Note: Java default password is 'changeit'.")
        elif not jks_data["entries"]:
            _print("  (empty keystore)")
        else:
            cert_formatter = CertFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
            key_formatter = KeyFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
            _ENTRY_LABELS = {"trusted_cert": "trustedCertEntry",
                             "private_key": "privateKeyEntry",
                             "secret_key": "secretKeyEntry"}
            idx = 0
            for entry in jks_data["entries"]:
                label = _ENTRY_LABELS.get(entry["type"], entry["type"])
                _print()
                _print(f"# - JKS alias: {entry['alias']}  ({label})")
                if entry["type"] == "trusted_cert" and entry["cert"]:
                    _print(cert_formatter.format(entry["cert"], idx, lvl))
                elif entry["type"] == "private_key":
                    for ci, cert in enumerate(entry["chain"]):
                        if ci > 0:
                            _print()
                        _print(cert_formatter.format(cert, idx, lvl))
                        idx += 1
                    if entry["key_info"]:
                        _print()
                        _print(key_formatter.format(entry["key_info"], 0, lvl))
                    idx -= 1  # adjust — will be incremented below
                elif entry["type"] == "secret_key":
                    sec = entry["secret"] or {}
                    algo = sec.get("algorithm", "Unknown")
                    bits = sec.get("key_size", 0)
                    _print(f"{idx}: Secret Key:")
                    _print(f"  Algorithm:       {algo}")
                    if bits:
                        _print(f"  Key Size:        {bits} bit")
                    _print(f"  *** SECRET KEY — handle with care ***")
                idx += 1

    elif fmt["type"] == "key":
        # Private key
        keys = load_keys(fmt["data"], fmt, password=pw_bytes)
        if verbose >= 1:
            _print(f"  # Loaded {len(keys)} private key(s)")
            _print(f"  # Format: {fmt['type']}/{fmt['encoding']}"
                   + (f"  (was base64)" if fmt["was_b64"] else "")
                   + (f"  (was JSON)" if fmt["was_json"] else ""))
        formatter = KeyFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
        for i, ki in enumerate(keys):
            _print()
            _print(formatter.format(ki, i, lvl))
        if save_file:
            _print()
            _print("-> Note: save_file is disabled for private keys (security).")

    elif fmt["type"] == "pubkey":
        # Public key
        pubs = load_public_keys(fmt["data"], fmt)
        if verbose >= 1:
            _print(f"  # Loaded {len(pubs)} public key(s)")
            _print(f"  # Format: {fmt['type']}/{fmt['encoding']}"
                   + (f"  (was base64)" if fmt["was_b64"] else "")
                   + (f"  (was JSON)" if fmt["was_json"] else ""))
        formatter = PublicKeyFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
        for i, pi in enumerate(pubs):
            _print()
            _print(formatter.format(pi, i, lvl))

    elif fmt["type"] == "csr":
        # CSR (PKCS#10)
        csrs = load_csrs(fmt["data"], fmt)
        if verbose >= 1:
            _print(f"  # Loaded {len(csrs)} CSR(s)")
            _print(f"  # Format: {fmt['type']}/{fmt['encoding']}"
                   + (f"  (was base64)" if fmt["was_b64"] else "")
                   + (f"  (was JSON)" if fmt["was_json"] else ""))
        formatter = CsrFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
        for i, csr in enumerate(csrs):
            _print()
            _print(formatter.format(csr, i, lvl))
        if save_file:
            _print()
            for i, csr in enumerate(csrs):
                out_name = f"cert_grep_output_{i}.csr.pem"
                with open(out_name, "wb") as f:
                    f.write(csr.public_bytes(serialization.Encoding.PEM))
                _print(f"-> CSR:  {os.path.abspath(out_name)}")

    elif fmt["type"] == "crl":
        # CRL (Certificate Revocation List)
        crls = load_crls(fmt["data"], fmt)
        if verbose >= 1:
            _print(f"  # Loaded {len(crls)} CRL(s)")
            _print(f"  # Format: {fmt['type']}/{fmt['encoding']}"
                   + (f"  (was base64)" if fmt["was_b64"] else "")
                   + (f"  (was JSON)" if fmt["was_json"] else ""))
        formatter = CrlFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
        for i, crl in enumerate(crls):
            _print()
            _print(formatter.format(crl, i, lvl))
        if save_file:
            _print()
            for i, crl in enumerate(crls):
                out_name = f"cert_grep_output_{i}.crl.pem"
                with open(out_name, "wb") as f:
                    f.write(crl.public_bytes(serialization.Encoding.PEM))
                _print(f"-> CRL:  {os.path.abspath(out_name)}")

    else:
        # Certificate (X.509 / PKCS#7)
        # Check if a private key is also present (cert + key bundle)
        # but only when the user didn't explicitly filter to a specific type
        has_key = (not force_type
                   and any(marker in fmt["data"] for marker in _PRIVATE_KEY_MARKERS))
        if has_key:
            _print("\n-> Note: this file also contains a private key.")
        certs = load_certs(fmt["data"], fmt)
        if verbose >= 1:
            _print()
            _print(f"  # Loaded {len(certs)} certificate(s)"
                   + (", plus private key" if has_key else ""))
            _print(f"  # Format: {fmt['type']}/{fmt['encoding']}"
                   + (f"  (was base64)" if fmt["was_b64"] else "")
                   + (f"  (was JSON)" if fmt["was_json"] else ""))
        formatter = CertFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)

        # Run chain verification first (if requested)
        vresult = None
        if verify_chain:
            if len(certs) >= 2:
                verifier = ChainVerifier(certs)
                vresult = verifier.verify()
                if verbose >= 1:
                    _print("  #")
                else:
                    _print()
                _print(format_chain_header(vresult))
            elif len(certs) == 1:
                _print()
                _print("  # Chain verification requires at least two certificates.")

        # Run weakness scan (if requested)
        wresult = None
        if weakness_scan and certs:
            scanner = WeaknessScanner(certs, config_paths=weak_configs)
            wresult = scanner.scan()
            if not vresult:
                if verbose >= 1:
                    _print("  #")
                else:
                    _print()
            _print(format_weak_header(wresult, ncerts=len(certs)))

        for i, cert in enumerate(certs):
            _print()
            if vresult:
                checks = format_chain_cert_checks(vresult, cert, display_idx=i)
                if checks:
                    _print()
                    _print(checks)
                    _print()
            if wresult and wresult["rules"] > 0:
                wchecks = format_weak_cert_checks(wresult, cert, display_idx=i)
                if wchecks:
                    if not vresult:
                        _print()
                    _print(wchecks)
                    _print()
            _print(formatter.format(cert, i, lvl))

        if vresult:
            # Build chain→display index mapping
            by_cert = vresult.get("by_cert", {})
            chain_to_display = {}
            for i, cert in enumerate(certs):
                entry = by_cert.get(id(cert))
                if entry:
                    chain_to_display[entry["index"]] = i
            _print()
            _print()
            _print(format_chain_result(vresult, chain_to_display))

        if wresult and wresult["rules"] > 0:
            weak_to_display = {i: i for i in range(len(certs))}
            if not vresult:
                _print()
            _print()
            _print(format_weak_result(wresult, weak_to_display))

        # Show bundled private key(s) with safe-metadata rules
        if has_key:
            try:
                keys = load_keys(fmt["data"], fmt, password=pw_bytes)
                key_formatter = KeyFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
                for i, ki in enumerate(keys):
                    _print()
                    _print(key_formatter.format(ki, i, lvl))
            except ValueError:
                pass  # key parsing failed — show certs without key

        if save_file:
            _save_certs = certs
            _save_has_key = has_key
        else:
            _save_certs = None
            _save_has_key = False

    _print(" ")

    text = "\n".join(lines)
    idx = cert_index if cert_index is not None else (0 if first_only else None)
    if idx is not None:
        text = _filter_cert_index(text, idx)
    if output is not None:
        print(text, file=output)

    # -- Post-output: save selected cert(s) to file --
    if save_file and _save_certs is not None:
        save_lines = []
        if idx is not None and idx >= len(_save_certs):
            save_lines.append(f"-> Not saving: index {idx} out of range ({len(_save_certs)} certificates)")
        else:
            save_list = [(idx, _save_certs[idx])] if idx is not None else list(enumerate(_save_certs))
            for i, cert in save_list:
                out_name = f"cert_grep_output_{i}.pem"
                with open(out_name, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                save_lines.append(f"-> Saved:  {os.path.abspath(out_name)}")
        if _save_has_key:
            save_lines.append("-> Note: private key not saved (security).")
        save_text = "\n".join(save_lines)
        if output is not None:
            print(save_text, file=output)
        text = text + "\n" + save_text

    return text


# ---------------------------------------------------------------------------
#  CLI entry point
# ---------------------------------------------------------------------------

def _resolve_password(pw_arg: str):
    """Resolve a PW= CLI argument to a password string, PasswordFile, or None.

    Supported forms:
        PW=<password>         Direct password (visible in ps/history — dev/test only)
        PW=prompt             Interactive getpass prompt
        PW=env:<VARNAME>      Read from environment variable
        PW=file:<path>        Single-line: read first line (backward compatible)
                              Multi-line:  parse as password file with mappings + defaults
    """
    if pw_arg.lower() == "prompt":
        import getpass
        return getpass.getpass("Password: ")
    if pw_arg.lower().startswith("env:"):
        varname = pw_arg[4:]
        val = os.environ.get(varname)
        if val is None:
            print(f"- Error: environment variable '{varname}' is not set.", file=sys.stderr)
            sys.exit(4)
        return val
    if pw_arg.lower().startswith("file:"):
        fpath = pw_arg[5:]
        try:
            with open(fpath, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"- Error: password file not found: {fpath}", file=sys.stderr)
            sys.exit(4)
        except Exception as e:
            print(f"- Error reading password file: {e}", file=sys.stderr)
            sys.exit(4)
        # Count non-blank, non-comment lines
        content_lines = [ln for ln in lines
                         if ln.strip() and not ln.strip().startswith("#")]
        if len(content_lines) <= 1:
            # Single-line file: backward-compatible, return plain string
            if content_lines:
                return content_lines[0].rstrip("\n\r")
            return ""
        # Multi-line: parse as password file
        return _parse_password_file(fpath)
    # Direct password
    return pw_arg


def _get_password_candidates(filename: str, file_pw, shared_pw) -> list:
    """Return ordered list of passwords to try for a file.

    Args:
        filename:   The filename (may include path)
        file_pw:    Per-file password from :PW= suffix (str or None)
        shared_pw:  Shared password from PW= (str, PasswordFile, or None)

    Returns:
        List of password strings to try (may include None for "no password").
    """
    # Per-file :PW= always wins
    if file_pw is not None:
        return [file_pw]
    # Shared password is a PasswordFile → resolve against filename
    if isinstance(shared_pw, PasswordFile):
        candidates = shared_pw.resolve(filename)
        if candidates:
            return candidates
        return [None]  # no match, no defaults — try without password
    # Shared password is a plain string
    if shared_pw is not None:
        return [shared_pw]
    return [None]


def _probe_password(data: bytes, fmt: dict, candidates: list) -> Optional[str]:
    """Try each password candidate on a password-protected container.

    Returns the first password that successfully decrypts, or the first
    candidate if the format doesn't require a password, or None if
    all candidates fail (caller should use None to get graceful error).
    """
    if fmt["type"] not in ("pkcs12", "jks"):
        return candidates[0] if candidates else None
    for pw in candidates:
        try:
            pw_bytes = _normalize_password(pw)
            if fmt["type"] == "pkcs12":
                p12 = load_pkcs12(data, fmt, password=pw_bytes)
                # Success if we get certs/key or it's genuinely empty
                if p12.get("cert") or p12.get("chain") or p12.get("key"):
                    return pw
                # Loaded OK but empty — might be unencrypted empty container
                if not p12.get("encrypted"):
                    return pw
            elif fmt["type"] == "jks":
                load_jks(data, fmt, password=pw_bytes)
                return pw  # success
        except (ValueError, Exception):
            continue
    # All candidates failed — return None to get graceful error message
    return None


def cert_grep_main():
    """Command-line interface — parses sys.argv and calls cert_grep()."""
    all_args = sys.argv[1:]

    if not all_args or "-h" in all_args or "--help" in all_args:
        cert_grep("--help")
        sys.exit(2)

    if "-V" in all_args or "--version" in all_args:
        cert_grep("--version")
        sys.exit(2)

    # -- Parse arguments --
    level = 1
    force_type = None
    force_enc = None
    force_b64 = False
    show_pub = False
    show_fp = False
    save_file = False
    first_only = False
    cert_index = None
    cert_files = []         # list of (filename, per_file_password|None)
    password = None          # shared password from PW=
    verify_chain = False
    weakness_scan = False
    weak_configs = None   # None = not specified; [] = specified but no valid files

    verbose = 0
    env_verbose = os.environ.get("VERBOSE", "")
    if env_verbose.strip().isdigit():
        verbose = int(env_verbose.strip())

    # -- Environment variable defaults (CLI args override these) --
    # CERTGREP_SUMMARY: default summary level (0-4 or "full")
    _env_summary = os.environ.get("CERTGREP_SUMMARY", "").strip().lower()
    if _env_summary:
        if   _env_summary in ("0", "summary_0", "summary0"):             level = 0
        elif _env_summary in ("1", "summary_1", "summary1", "summary"):  level = 1
        elif _env_summary in ("2", "summary_2", "summary2"):             level = 2
        elif _env_summary in ("3", "summary_3", "summary3"):             level = 3
        elif _env_summary in ("4", "summary_4", "summary4", "full"):     level = 4
        else:
            print(f"- Warning: CERTGREP_SUMMARY='{_env_summary}' unrecognised, ignored "
                  f"(valid: 0-4, full)", file=sys.stderr)

    # CERTGREP_CNUM: default cert index / first-only (0=c0, N=cN)
    _env_cnum = os.environ.get("CERTGREP_CNUM", "").strip()
    if _env_cnum:
        if _env_cnum.isdigit():
            _n = int(_env_cnum)
            if _n == 0:
                first_only = True
            else:
                cert_index = _n
        else:
            print(f"- Warning: CERTGREP_CNUM='{_env_cnum}' must be a non-negative integer, "
                  f"ignored", file=sys.stderr)

    # CERTGREP_FP: enable fingerprints by default
    _env_fp = os.environ.get("CERTGREP_FP", "").strip().lower()
    if _env_fp == "yes":
        show_fp = True
    elif _env_fp and _env_fp != "no":
        print(f"- Warning: CERTGREP_FP='{_env_fp}' — only 'yes' or 'no' supported, ignored",
              file=sys.stderr)

    # CERTGREP_PUB: enable public key details by default
    _env_pub = os.environ.get("CERTGREP_PUB", "").strip().lower()
    if _env_pub == "yes":
        show_pub = True
    elif _env_pub and _env_pub != "no":
        print(f"- Warning: CERTGREP_PUB='{_env_pub}' — only 'yes' or 'no' supported, ignored",
              file=sys.stderr)

    for arg in all_args:
        a = arg.lower()
        if   a in ("summary_0","summary0","0"):           level = 0
        elif a in ("summary_1","summary1","1","summary"): level = 1
        elif a in ("summary_2","summary2","2"):           level = 2
        elif a in ("summary_3","summary3","3"):           level = 3
        elif a in ("summary_4","summary4","4","full"):    level = 4

        elif a == "pem":                                  force_enc = "pem"
        elif a == "der":                                  force_enc = "der"

        elif a == "x509":                                 force_type = "x509"
        elif a in ("p7","pkcs7","pkcs#7"):                force_type = "pkcs7"
        elif a in ("csr","pkcs10","pkcs#10","req"):       force_type = "csr"
        elif a == "crl":                                  force_type = "crl"
        elif a in ("key","privkey","privatekey"):         force_type = "key"
        elif a in ("pubkey","publickey"):                 force_type = "pubkey"
        elif a in ("p12","pkcs12","pkcs#12","pfx"):       force_type = "pkcs12"
        elif a in ("jks","jceks","keystore"):             force_type = "jks"

        elif a == "b64":                                  force_b64 = True

        elif a == "pub":                                  show_pub = True
        elif a == "fp":                                   show_fp = True
        elif a in ("file","preserve","x"):                save_file = True
        elif a == "c0":                                   first_only = True
        elif re.match(r"c\d+$", a):                       cert_index = int(a[1:])
        elif a in ("-v","--verbose"):                     verbose += 1
        elif a in ("ver","verify"):                    verify_chain = True
        elif a == "weak":                              weakness_scan = True
        elif arg.upper().startswith("WEAK="):
            weakness_scan = True
            if weak_configs is None:
                weak_configs = []
            import glob as _glob
            for pattern in arg[5:].split(","):
                pattern = pattern.strip()
                if not pattern:
                    continue
                matched = _glob.glob(pattern)
                if matched:
                    weak_configs.extend(matched)
                elif os.path.isfile(pattern):
                    weak_configs.append(pattern)
                else:
                    print(f"- Warning: weakness config not found: {pattern}", file=sys.stderr)
        elif arg.upper().startswith("PW="):               password = _resolve_password(arg[3:])
        else:
            # Detect common PW= typos before treating as filename
            _pw_typo = arg.upper()
            if re.match(r'^PW[:.]', _pw_typo):
                # PW:file=path → PW=file:path  (swapped : and =)
                rest = arg[3:]  # after "PW:" or "PW."
                eq_pos = rest.find("=")
                if eq_pos > 0:
                    # PW:file=path → PW=file:path
                    suggestion = f"PW={rest[:eq_pos]}:{rest[eq_pos+1:]}"
                else:
                    suggestion = f"PW={rest}"
                print(f"- Warning: '{arg}' looks like a mistyped password option.",
                      file=sys.stderr)
                print(f"  Did you mean: {suggestion}",
                      file=sys.stderr)
                sys.exit(4)

            # File argument — check for :PW= per-file password suffix
            file_pw = None
            filename = arg
            # Search for :PW= (case-insensitive on PW=) — use last occurrence
            upper = arg.upper()
            pw_pos = upper.rfind(":PW=")
            if pw_pos > 0:  # must have at least 1 char before :PW=
                filename = arg[:pw_pos]
                file_pw = _resolve_password(arg[pw_pos + 4:])
            cert_files.append((filename, file_pw))

    if not cert_files:
        cert_grep("--help")
        sys.exit(2)

    # -- Single file: original behavior (exit code on error) --
    if len(cert_files) == 1:
        fname, file_pw = cert_files[0]
        candidates = _get_password_candidates(fname, file_pw, password)
        if len(candidates) > 1:
            # Multiple candidates — probe to find the right one
            try:
                data = Path(fname).read_bytes()
                fmt = detect_format(data, fname)
                effective_pw = _probe_password(data, fmt, candidates)
            except Exception:
                effective_pw = candidates[0]  # let cert_grep handle the error
        else:
            effective_pw = candidates[0]
        try:
            cert_grep(
                source=fname,
                level=level,
                verbose=verbose,
                show_pub=show_pub,
                show_fp=show_fp,
                save_file=save_file,
                force_type=force_type,
                force_encoding=force_enc,
                force_b64=force_b64,
                first_only=first_only,
                cert_index=cert_index,
                password=effective_pw,
                verify_chain=verify_chain,
                weakness_scan=weakness_scan,
                weak_configs=weak_configs,
            )
        except FileNotFoundError as e:
            print(f"\n- Error 15: {e}\n", file=sys.stderr)
            sys.exit(15)
        except ValueError as e:
            print(f"\n{e}", file=sys.stderr)
            print(f"\n- Error 16: cert_grep error.\n", file=sys.stderr)
            sys.exit(1)
        return

    # -- Multi-file mode --
    # When ver or weak is requested, use two-pass strategy:
    #   Pass 1: load all files, collect certs, run cross-file analysis
    #   Pass 2: display per-file with inline annotations
    # When neither is requested, simple per-file processing.

    if not verify_chain and not weakness_scan:
        # Simple per-file processing — no cross-file analysis needed
        errors = 0
        for i, (fname, file_pw) in enumerate(cert_files):
            candidates = _get_password_candidates(fname, file_pw, password)
            if len(candidates) > 1:
                try:
                    data = Path(fname).read_bytes()
                    fmt = detect_format(data, fname)
                    effective_pw = _probe_password(data, fmt, candidates)
                except Exception:
                    effective_pw = candidates[0]
            else:
                effective_pw = candidates[0]
            if i > 0:
                print()
            print(f"# FILE: {fname}")
            try:
                cert_grep(
                    source=fname,
                    level=level,
                    verbose=verbose,
                    show_pub=show_pub,
                    show_fp=show_fp,
                    save_file=save_file,
                    force_type=force_type,
                    force_encoding=force_enc,
                    force_b64=force_b64,
                    first_only=first_only,
                    cert_index=cert_index,
                    password=effective_pw,
                    verify_chain=False,
                    weakness_scan=False,
                    weak_configs=None,
                )
            except FileNotFoundError as e:
                print(f"x Error: {e}", file=sys.stderr)
                errors += 1
            except Exception as e:
                print(f"x Error: {e}", file=sys.stderr)
                errors += 1
        if errors:
            print(f"\n# {errors} file(s) had errors", file=sys.stderr)
            sys.exit(1)
        return

    # -- Two-pass multi-file with cross-file ver/weak --
    lvl = _LEVEL_MAP.get(level)
    if lvl is None:
        lvl = "summary_1"
    if lvl in ("summary_2", "summary_3"):
        show_fp = True

    # Pass 1: Load all files, collect certs for cross-file analysis
    #   file_entries: list of (filename, "cert"|"other", certs[], has_key, fmt, pw)
    file_entries = []
    all_certs = []          # combined cert list for ChainVerifier/WeaknessScanner
    all_cert_files = []     # (global_start_idx, filename) for each cert-bearing file
    errors = 0

    for fname, file_pw in cert_files:
        candidates = _get_password_candidates(fname, file_pw, password)
        try:
            p = Path(fname)
            if not p.exists():
                raise FileNotFoundError(f"can't read file: {fname}")
            data = p.read_bytes()
            fmt = detect_format(data, fname)
            if force_type:      fmt["type"] = force_type
            if force_enc:       fmt["encoding"] = force_enc
            if force_b64 and not fmt["was_b64"]:
                decoded = try_b64_decode(data)
                if decoded:
                    fmt["data"] = decoded
                    fmt["was_b64"] = True

            # Probe for working password if multiple candidates
            if len(candidates) > 1 and fmt["type"] in ("pkcs12", "jks"):
                effective_pw = _probe_password(fmt["data"], fmt, candidates)
            else:
                effective_pw = candidates[0]

            pw_bytes = _normalize_password(effective_pw)

            if fmt["type"] in ("x509", "pkcs7"):
                has_key = (not force_type
                           and any(m in fmt["data"] for m in _PRIVATE_KEY_MARKERS))
                certs = load_certs(fmt["data"], fmt)
                global_start = len(all_certs)
                all_certs.extend(certs)
                all_cert_files.append((global_start, fname))
                file_entries.append((fname, "cert", certs, has_key, fmt, pw_bytes))
            elif fmt["type"] == "pkcs12":
                # PKCS#12: extract certs for cross-file analysis
                try:
                    p12 = load_pkcs12(fmt["data"], fmt, password=pw_bytes)
                except ValueError as e:
                    if "Incorrect password" in str(e):
                        p12 = {"encrypted": True, "bad_password": True,
                               "cert": None, "chain": [], "key": None}
                    else:
                        raise
                p12_certs = []
                if p12.get("cert"):
                    p12_certs.append(p12["cert"])
                p12_certs.extend(p12.get("chain", []))
                if p12_certs:
                    global_start = len(all_certs)
                    all_certs.extend(p12_certs)
                    all_cert_files.append((global_start, fname))
                file_entries.append((fname, "pkcs12", p12_certs, p12, fmt, pw_bytes))
            elif fmt["type"] == "jks":
                # JKS/JCEKS: extract certs from entries for cross-file analysis
                jks_data = load_jks(fmt["data"], fmt, password=pw_bytes)
                jks_certs = []
                for entry in jks_data.get("entries", []):
                    if entry["type"] == "trusted_cert" and entry.get("cert"):
                        jks_certs.append(entry["cert"])
                    elif entry["type"] == "private_key":
                        jks_certs.extend(entry.get("chain", []))
                if jks_certs:
                    global_start = len(all_certs)
                    all_certs.extend(jks_certs)
                    all_cert_files.append((global_start, fname))
                file_entries.append((fname, "jks", jks_certs, jks_data, fmt, pw_bytes))
            else:
                # Non-cert types (key, CSR, CRL, pubkey) — process via cert_grep()
                file_entries.append((fname, "other", [], None, fmt, pw_bytes))
        except FileNotFoundError as e:
            file_entries.append((fname, "error", [], str(e), None, None))
            errors += 1
        except Exception as e:
            file_entries.append((fname, "error", [], f"loading {fname}: {e}", None, None))
            errors += 1

    # Run cross-file analysis on combined cert list
    vresult = None
    wresult = None
    if verify_chain and len(all_certs) >= 2:
        verifier = ChainVerifier(all_certs)
        vresult = verifier.verify()
    if weakness_scan and all_certs:
        scanner = WeaknessScanner(all_certs, config_paths=weak_configs)
        wresult = scanner.scan()

    # Pass 2: Display per-file with inline annotations
    formatter = CertFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
    key_formatter = KeyFormatter(verbose=verbose, show_pub=show_pub, show_fp=show_fp)
    global_idx = 0
    first_file = True

    # Print cross-file headers once, before the first filename
    header_printed = False

    for fname, ftype, certs, extra, fmt, pw_bytes in file_entries:
        # Print cross-file header before the very first cert-bearing file
        if not header_printed and ftype in ("cert", "pkcs12", "jks"):
            if vresult:
                print(format_chain_header(vresult))
            if wresult:
                if vresult:
                    print("  #")
                print(format_weak_header(wresult, ncerts=len(all_certs)))
            if vresult or wresult:
                print()
            header_printed = True

        if not first_file:
            print()    # double blank line before each # filename
            print()
        first_file = False
        print(f"# FILE: {fname}")

        if ftype == "error":
            print(f"x Error: {extra}", file=sys.stderr)
            continue

        if ftype == "other":
            # Non-cert: delegate to cert_grep() for full handling
            try:
                cert_grep(
                    source=fname,
                    level=level,
                    verbose=verbose,
                    show_pub=show_pub,
                    show_fp=show_fp,
                    save_file=save_file,
                    force_type=force_type,
                    force_encoding=force_enc,
                    force_b64=force_b64,
                    first_only=first_only,
                    cert_index=cert_index,
                    password=pw_bytes,
                    verify_chain=False,
                    weakness_scan=False,
                )
            except Exception as e:
                print(f"x Error: {e}", file=sys.stderr)
                errors += 1
            continue

        # Cert or PKCS12 file — display with inline annotations
        if ftype == "cert":
            has_key = extra  # extra is has_key for cert type
            if has_key:
                print("\n-> Note: this file also contains a private key.")

            for ci, cert in enumerate(certs):
                if ci > 0:
                    print()
                if vresult:
                    checks = format_chain_cert_checks(vresult, cert, display_idx=global_idx)
                    if checks:
                        print()
                        print(checks)
                        print()
                if wresult and wresult.get("rules", 0) > 0:
                    wchecks = format_weak_cert_checks(wresult, cert, display_idx=global_idx)
                    if wchecks:
                        if not vresult:
                            print()
                        print(wchecks)
                        print()
                print(formatter.format(cert, global_idx, lvl))
                global_idx += 1

            # Show bundled private key(s)
            if has_key:
                try:
                    keys = load_keys(fmt["data"], fmt, password=pw_bytes)
                    for i, ki in enumerate(keys):
                        print()
                        print(key_formatter.format(ki, i, lvl))
                except ValueError:
                    pass

        elif ftype == "pkcs12":
            p12 = extra  # extra is p12 dict for pkcs12 type
            print()
            print("PKCS#12 Container:")

            if p12.get("bad_password"):
                print("  *** Incorrect password for PKCS#12 container ***")
                print("  Hint: use PW=<password> to supply the correct passphrase.")
            elif p12.get("encrypted") and not certs and not p12.get("key"):
                print("  *** Password-protected PKCS#12 — cannot inspect without passphrase ***")
                print("  Hint: use PW=<password> to supply the passphrase.")

            for ci, cert in enumerate(certs):
                if ci > 0:
                    print()
                if vresult:
                    checks = format_chain_cert_checks(vresult, cert, display_idx=global_idx)
                    if checks:
                        print()
                        print(checks)
                        print()
                if wresult and wresult.get("rules", 0) > 0:
                    wchecks = format_weak_cert_checks(wresult, cert, display_idx=global_idx)
                    if wchecks:
                        if not vresult:
                            print()
                        print(wchecks)
                        print()
                print(formatter.format(cert, global_idx, lvl))
                global_idx += 1

            # Show private key summary from PKCS#12
            if p12.get("key"):
                ki = p12["key"]
                print()
                print(key_formatter.format(ki, 0, lvl))

        elif ftype == "jks":
            jks_data = extra  # extra is jks_data dict
            store_type = jks_data["store_type"].upper()
            print()
            print(f"{store_type} KeyStore:")

            if jks_data.get("bad_password"):
                print(f"  *** Incorrect password for {store_type} KeyStore ***")
                print("  Hint: use PW=<password> to supply the correct passphrase.")
            elif jks_data.get("encrypted") and not jks_data.get("entries"):
                print(f"  *** Password-protected {store_type} — cannot inspect without passphrase ***")
                print("  Hint: use PW=<password> to supply the passphrase.")
                print("  Note: Java default password is 'changeit'.")
            elif not jks_data.get("entries"):
                print("  (empty keystore)")
            else:
                _ENTRY_LABELS = {"trusted_cert": "trustedCertEntry",
                                 "private_key": "privateKeyEntry",
                                 "secret_key": "secretKeyEntry"}
                for entry in jks_data["entries"]:
                    label = _ENTRY_LABELS.get(entry["type"], entry["type"])
                    print()
                    print(f"# - JKS alias: {entry['alias']}  ({label})")
                    if entry["type"] == "trusted_cert" and entry.get("cert"):
                        cert = entry["cert"]
                        if vresult:
                            checks = format_chain_cert_checks(vresult, cert, display_idx=global_idx)
                            if checks:
                                print(checks)
                        if wresult and wresult.get("rules", 0) > 0:
                            wchecks = format_weak_cert_checks(wresult, cert, display_idx=global_idx)
                            if wchecks:
                                print(wchecks)
                        print(formatter.format(cert, global_idx, lvl))
                        global_idx += 1
                    elif entry["type"] == "private_key":
                        for ci, cert in enumerate(entry.get("chain", [])):
                            if ci > 0:
                                print()
                            if vresult:
                                checks = format_chain_cert_checks(vresult, cert, display_idx=global_idx)
                                if checks:
                                    print(checks)
                            if wresult and wresult.get("rules", 0) > 0:
                                wchecks = format_weak_cert_checks(wresult, cert, display_idx=global_idx)
                                if wchecks:
                                    print(wchecks)
                            print(formatter.format(cert, global_idx, lvl))
                            global_idx += 1
                        if entry.get("key_info"):
                            print()
                            print(key_formatter.format(entry["key_info"], 0, lvl))
                    elif entry["type"] == "secret_key":
                        sec = entry.get("secret") or {}
                        algo = sec.get("algorithm", "Unknown")
                        bits = sec.get("key_size", 0)
                        print(f"{global_idx}: Secret Key:")
                        print(f"  Algorithm:       {algo}")
                        if bits:
                            print(f"  Key Size:        {bits} bit")
                        print(f"  *** SECRET KEY — handle with care ***")

    # Print cross-file result footers
    if vresult:
        by_cert = vresult.get("by_cert", {})
        chain_to_display = {}
        for gi, cert in enumerate(all_certs):
            entry = by_cert.get(id(cert))
            if entry:
                chain_to_display[entry["index"]] = gi
        print()
        print()
        print(format_chain_result(vresult, chain_to_display))
        print()

    if wresult and wresult.get("rules", 0) > 0:
        weak_to_display = {i: i for i in range(len(all_certs))}
        if not vresult:
            print()
        print()
        print(format_weak_result(wresult, weak_to_display))
        print()

    if verify_chain and len(all_certs) < 2:
        print()
        print("  # Chain verification requires at least two certificates"
              f" ({len(all_certs)} found across {len(cert_files)} file(s)).")
        print()

    if errors:
        print(f"\n# {errors} file(s) had errors", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cert_grep_main()
