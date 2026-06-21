#!/usr/bin/env python3
"""
ssl-grep.py  -  TLS Certificate Inspector

Connects to an SSL/TLS endpoint and displays the X.509 certificate chain.
Pure Python replacement for openssl s_client + cert_grep.

Copyright (c) 2026, Mountain Informatik GmbH. All rights reserved.
Original software by John Buehrer.

Requirements:
    pip install cryptography
    cert-grep.py  (same directory or in $PATH / sys.path / $PYTHONPATH)

Usage:
    $ ssl-grep.py  https://example.com
    $ ssl-grep.py  https://example.com  summary_0  pub
    $ ssl-grep.py  example.com:443  2  fp
    $ ssl-grep.py  https://one.com  https://two.com  summary_0
"""

__version__ = "4.12.0"
__origin__  = "f_ssl_grep v11.0.0 (bashrc_101_i)"

import sys
import os
import re
import ssl
import _ssl
import socket
import base64
import ctypes
import ctypes.util
import warnings

from pathlib import Path
from typing import Optional, List, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
#  Import cert-grep as a library
# ---------------------------------------------------------------------------

def _import_cert_grep():
    """Import cert-grep, searching common locations."""
    import importlib
    try:
        _mod = importlib.import_module("cert-grep")
        return _mod.cert_grep, _mod.__version__
    except (ImportError, ModuleNotFoundError):
        pass

    # Try same directory as this script
    script_dir = Path(__file__).resolve().parent
    if script_dir not in sys.path:
        sys.path.insert(0, str(script_dir))
    try:
        _mod = importlib.import_module("cert-grep")
        return _mod.cert_grep, _mod.__version__
    except (ImportError, ModuleNotFoundError):
        pass

    print("Error: 'cert-grep.py' is required but not found.", file=sys.stderr)
    print("  Place cert-grep.py in the same directory as ssl-grep.py,", file=sys.stderr)
    print("  or install it in your Python path: $PYTHONPATH", file=sys.stderr)
    sys.exit(1)


cert_grep, _cert_grep_version = _import_cert_grep()


# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

_DEFAULT_PORT     = 443
_CONNECT_TIMEOUT  = 5       # TCP connect timeout (seconds) — replaces nc check
_SSL_TIMEOUT      = 10      # TLS handshake timeout (seconds)

# Env var overrides:
#   SSLGREP_TIMEOUT      — override connect timeout
#   SSLGREP_NO_TIMEOUT   — suppress timeout protection


# ---------------------------------------------------------------------------
#  URL / Host Parsing
# ---------------------------------------------------------------------------

def parse_target(target: str) -> Tuple[str, int]:
    """Parse a host/URL into (hostname, port).

    Accepts:
        example.com                 → (example.com, 443)
        example.com:446             → (example.com, 446)
        https://example.com/        → (example.com, 443)
        https://example.com:446/p   → (example.com, 446)
        http://example.com/         → (example.com, 443)
    """
    raw = target.strip()

    # Strip protocol prefix
    if re.match(r'https?://', raw, re.I):
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port or _DEFAULT_PORT
        return host, port

    # host:port
    if ":" in raw:
        parts = raw.split(":", 1)
        host = parts[0].strip("/")
        try:
            port = int(parts[1].strip("/"))
        except ValueError:
            port = _DEFAULT_PORT
        return host, port

    # bare hostname
    return raw.strip("/"), _DEFAULT_PORT


def is_ip_address(host: str) -> bool:
    """True if host looks like an IP address (skip SNI)."""
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        pass
    return False


# ---------------------------------------------------------------------------
#  Proxy Support
# ---------------------------------------------------------------------------

def get_proxy() -> Optional[Tuple[str, int]]:
    """Read proxy from environment (https_proxy / http_proxy).

    Returns (proxy_host, proxy_port) or None.
    """
    proxy_url = os.environ.get("https_proxy") or os.environ.get("http_proxy") or ""
    if not proxy_url:
        return None

    m = re.match(r'https?://([^:]+):(\d+)/?', proxy_url)
    if m:
        return m.group(1), int(m.group(2))

    # Try host:port without scheme
    m = re.match(r'([^:]+):(\d+)/?$', proxy_url)
    if m:
        return m.group(1), int(m.group(2))

    return None


def connect_via_proxy(proxy_host: str, proxy_port: int,
                      target_host: str, target_port: int,
                      timeout: float, verbose: int = 0) -> socket.socket:
    """Establish a TCP tunnel via HTTP CONNECT proxy."""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    connect_req = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"\r\n"
    ).encode()

    if verbose >= 2:
        print(f"  # CONNECT {target_host}:{target_port} via {proxy_host}:{proxy_port}")

    sock.sendall(connect_req)

    # Read proxy response
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            sock.close()
            raise ConnectionError(f"Proxy closed connection during CONNECT")
        response += chunk

    status_line = response.split(b"\r\n", 1)[0].decode(errors="replace")
    if verbose >= 2:
        print(f"  # Proxy response: {status_line}")

    if b"200" not in response.split(b"\r\n", 1)[0]:
        sock.close()
        raise ConnectionError(f"Proxy CONNECT failed: {status_line}")

    return sock


# ---------------------------------------------------------------------------
#  TLS Connection & Certificate Extraction
# ---------------------------------------------------------------------------

# --- OpenSSL 3.x Legacy Provider ---
#
# OpenSSL 3.0+ removed many obsolete ciphers (RC4, DES, MD5-based, export
# grades) from the default provider.  They still exist in the "legacy"
# provider but must be explicitly loaded.  For an inspection tool this is
# necessary: we want to see the cert, not protect the connection.
#
# The legacy provider is loaded once, on first need, via ctypes.  If it
# fails (e.g. OpenSSL < 3, or the legacy provider .so is not installed),
# we fall back gracefully — no error, just fewer ciphers available.

_legacy_provider_loaded = False   # module-level, loaded at most once

def _load_openssl_legacy_provider(verbose: int = 0) -> bool:
    """Load the OpenSSL 3.x legacy provider for obsolete ciphers.

    Returns True if the provider was loaded (or was already loaded).
    Returns False if not needed (OpenSSL < 3) or loading failed.
    """
    global _legacy_provider_loaded
    if _legacy_provider_loaded:
        return True

    # Only needed for OpenSSL 3.x+
    if ssl.OPENSSL_VERSION_INFO[0] < 3:
        return False

    try:
        # OSSL_PROVIDER_load lives in libcrypto, not libssl
        libcrypto_name = ctypes.util.find_library("crypto")
        if not libcrypto_name:
            # macOS: try explicit paths
            for candidate in [
                "libcrypto.dylib",
                "/usr/lib/libcrypto.dylib",
                "/opt/homebrew/lib/libcrypto.dylib",
            ]:
                try:
                    ctypes.CDLL(candidate)
                    libcrypto_name = candidate
                    break
                except OSError:
                    continue
        if not libcrypto_name:
            return False

        libcrypto = ctypes.CDLL(libcrypto_name)

        # OSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *ctx, const char *name)
        _fn = libcrypto.OSSL_PROVIDER_load
        _fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _fn.restype = ctypes.c_void_p

        # Load the legacy provider into the default library context (NULL).
        # IMPORTANT: explicitly loading any provider disables OpenSSL's
        # auto-loading of the default provider.  We must load both.
        r_default = _fn(None, b"default")
        r_legacy = _fn(None, b"legacy")
        if r_legacy:
            _legacy_provider_loaded = True
            if verbose >= 2:
                print("  # OpenSSL legacy provider loaded (RC4, DES, etc.)")
            return True

        return False

    except (OSError, AttributeError):
        return False


def _make_ssl_context(permissive: bool = False,
                      use_legacy_provider: bool = False) -> ssl.SSLContext:
    """Create an SSL context for certificate inspection.

    Args:
        permissive:  If True, accept weak ciphers and older TLS versions.
                     This is a diagnostic tool — we want to see the cert,
                     not protect the connection.
        use_legacy_provider:  If True (implies permissive), also attempt to
                     load the OpenSSL 3.x legacy provider for obsolete
                     ciphers (RC4, DES, export-grade, etc.).
    """
    if use_legacy_provider:
        permissive = True

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE         # Accept all certs, like s_client

    if not permissive:
        ctx.set_alpn_protocols(["h2", "http/1.1"])

    if permissive:
        # In legacy-provider mode, also try without ALPN — some ancient
        # servers choke on TLS extensions they don't understand.
        if not use_legacy_provider:
            ctx.set_alpn_protocols(["h2", "http/1.1"])

        # Accept all ciphers including weak/legacy ones
        try:
            ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
        except ssl.SSLError:
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                ctx.set_ciphers("DEFAULT")

        # Allow TLS 1.0+ (for legacy servers)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except (ValueError, AttributeError):
                pass

        # Disable strict options that reject legacy servers
        ctx.options &= ~ssl.OP_NO_SSLv3     # Cautiously allow SSLv3
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT

    return ctx


def _tcp_connect(host: str, port: int, timeout: float,
                 proxy: Optional[Tuple[str, int]], verbose: int) -> socket.socket:
    """Establish a TCP connection, optionally through a proxy."""
    try:
        if proxy:
            return connect_via_proxy(
                proxy[0], proxy[1], host, port, timeout, verbose
            )
        else:
            return socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        raise ConnectionError(
            f"connection timeout after {timeout}s to {host}:{port}")
    except OSError as e:
        err_str = str(e)
        if "[Errno" in err_str:
            err_detail = err_str.replace("[Errno", "\n  [Errno")
        else:
            err_detail = " " + err_str
        raise ConnectionError(
            f"connection failed to {host}:{port}:{err_detail}"
        )


def get_server_certificates(host: str, port: int,
                            timeout: float = _SSL_TIMEOUT,
                            verbose: int = 0,
                            no_proxy: bool = False,
                            no_verify_ssl: bool = False) -> Tuple[bytes, int]:
    """Connect to host:port via TLS and return the certificate chain as PEM bytes.

    Tries a normal TLS handshake first.  On failure, retries with a permissive
    context (weak ciphers, older TLS versions) so that even legacy servers can
    be inspected.

    Returns:
        (pem_data, cert_count) — PEM bytes with all certificates, and the count.

    Raises:
        ConnectionError:  TCP connection or proxy failure.
        ssl.SSLError:     TLS handshake failure (after all retries).
        socket.timeout:   Connection timeout.
    """
    connect_timeout = timeout
    no_timeout = os.environ.get("SSLGREP_NO_TIMEOUT", "")

    # Override timeout from env
    env_timeout = os.environ.get("SSLGREP_TIMEOUT", "")
    if env_timeout.strip().isdigit():
        connect_timeout = int(env_timeout.strip())

    if no_timeout:
        connect_timeout = 30    # generous fallback, but not infinite

    sni = None if is_ip_address(host) else host
    proxy = None if no_proxy else get_proxy()

    if verbose >= 1:
        proxy_str = f" via proxy {proxy[0]}:{proxy[1]}" if proxy else ""
        sni_str = f" (SNI: {sni})" if sni else " (no SNI, IP address)"
        print(f"-$ ssl_connect {host}:{port}{sni_str}{proxy_str}")

    if verbose >= 2:
        if proxy:
            print(f"  # https_proxy: {os.environ.get('https_proxy', '')}")
            print(f"  # http_proxy:  {os.environ.get('http_proxy', '')}")
            print(f"  # proxy:       {proxy[0]}:{proxy[1]}")

    # --- TCP connection (replaces nc check) ---
    sock = _tcp_connect(host, port, connect_timeout, proxy, verbose)

    if verbose >= 1:
        print(f"  # TCP connected to {host}:{port}")

    # --- TLS handshake: progressive fallback ---
    #
    # Attempt 1:  Standard TLS context (modern ciphers, TLS 1.2+)
    # Attempt 2:  Permissive context  (all ciphers, TLS 1.0+, SSLv3)
    # Attempt 3:  Legacy provider     (OpenSSL 3.x: load RC4, DES, etc.)
    # Attempt 4:  Legacy + no SNI     (some ancient servers reject SNI)
    #
    # This is a diagnostic tool — we want to see the cert, not protect
    # the connection.  Matches the openssl s_client behaviour.

    #              (permissive, legacy_provider, try_sni, label)
    attempts = [
        (False, False, True,  "standard TLS"),
        (True,  False, True,  "permissive TLS (legacy ciphers/versions)"),
        (True,  True,  True,  "legacy provider (obsolete ciphers)"),
        (True,  True,  False, "legacy provider, no SNI"),
    ]

    last_err = None
    ssock = None
    connected_label = "standard TLS"

    for attempt_idx, (permissive, legacy, try_sni, label) in enumerate(attempts):
        # Skip legacy-provider attempts if loading failed or not needed
        if legacy and not _load_openssl_legacy_provider(verbose):
            if verbose >= 1:
                print(f"  # {label}: skipped (legacy provider not available)")
            continue

        ctx = _make_ssl_context(permissive=permissive,
                                use_legacy_provider=legacy)

        sni_for_attempt = sni if try_sni else None

        try:
            ssock = ctx.wrap_socket(sock, server_hostname=sni_for_attempt)
            connected_label = label
            if verbose >= 1 and (permissive or not try_sni):
                print(f"  # Connected with {label}")
            break       # success
        except (ssl.SSLError, OSError) as e:
            last_err = e
            if verbose >= 1:
                print(f"  # {label}: failed ({type(e).__name__})")
            # Socket is dead after a failed handshake — reconnect for retry
            try:
                sock.close()
            except OSError:
                pass

            # Find the next non-skippable attempt for the retry message
            next_attempt = None
            for future_idx in range(attempt_idx + 1, len(attempts)):
                fp, fl, fs, flabel = attempts[future_idx]
                if fl and not _legacy_provider_loaded:
                    continue    # will be skipped
                next_attempt = flabel
                break

            if next_attempt:
                if verbose >= 1:
                    print(f"  # Retrying with {next_attempt}...")
                try:
                    sock = _tcp_connect(host, port, connect_timeout,
                                        proxy, verbose)
                except ConnectionError:
                    break       # can't reconnect, give up
            # else: last attempt, fall through to error

    if ssock is None:
        # All attempts failed — build a helpful error message
        err_str = str(last_err)
        hint = ""
        if sni is None and "handshake" in err_str.lower():
            hint = (
                "\n  Hint: This IP address was contacted without SNI "
                "(Server Name Indication)."
                "\n        Many servers (eg CDNs like Cloudflare, Akamai) "
                "require a hostname."
                "\n        Try:  ssl-grep.py <hostname>   instead of "
                "the IP address."
            )
        elif "handshake" in err_str.lower():
            # If all attempts (including no-SNI) failed with the same
            # alert, the server likely has no TLS configured at all for
            # this hostname — not a cipher/protocol mismatch.
            if "alert handshake failure" in err_str.lower():
                hint = (
                    "\n  Hint: The server immediately rejected every "
                    "TLS handshake attempt,"
                    "\n        including with no SNI and all available "
                    "cipher suites."
                    "\n        This usually means the server has no TLS "
                    "certificate configured"
                    "\n        for this hostname.  Check whether the site "
                    "is HTTP-only, or whether"
                    "\n        TLS provisioning (e.g. Let's Encrypt) has "
                    "not completed."
                    f"\n        Diagnostic:  curl -sI http://{host}/"
                )
            else:
                hint = (
                    "\n  Hint: The server rejected all TLS handshake "
                    "attempts."
                    "\n        This may indicate the server requires "
                    "cipher suites or protocols"
                    "\n        that your OpenSSL build does not support."
                    f"\n        (OpenSSL: {ssl.OPENSSL_VERSION})"
                    "\n        Diagnostic:  openssl s_client -connect "
                    f"{host}:{port}"
                )
        err_lines = err_str.replace('] ', ']\n  ')
        raise ConnectionError(
            f"TLS handshake failed with {host}:{port}:\n"
            f"  {err_lines}{hint}"
        )

    # --- Connection quality warning ---
    tls_version = ssock.version()
    cipher_name = ssock.cipher()[0]
    cipher_bits = ssock.cipher()[2]

    if verbose >= 1:
        print(f"  # TLS: {tls_version}, cipher: {cipher_name}")

    # Warn about insecure connection parameters (always, not just verbose)
    insecure_warnings = []

    # Protocol version warnings
    if tls_version in ("SSLv3", "TLSv1", "TLSv1.0"):
        insecure_warnings.append(
            f"protocol {tls_version} is obsolete and insecure")
    elif tls_version in ("TLSv1.1",):
        insecure_warnings.append(
            f"protocol {tls_version} is deprecated")

    # Cipher warnings
    cipher_lower = cipher_name.lower()
    if "rc4" in cipher_lower:
        insecure_warnings.append(
            f"cipher {cipher_name} (RC4) is broken")
    elif "des" in cipher_lower and "aes" not in cipher_lower:
        insecure_warnings.append(
            f"cipher {cipher_name} (DES/3DES) is weak")
    elif "null" in cipher_lower:
        insecure_warnings.append(
            f"cipher {cipher_name} provides no encryption")
    elif "export" in cipher_lower:
        insecure_warnings.append(
            f"cipher {cipher_name} is export-grade (weak)")

    if cipher_bits and cipher_bits < 128:
        insecure_warnings.append(
            f"effective key strength is only {cipher_bits} bits")

    if insecure_warnings:
        print()
        print(f"! WARNING: insecure TLS connection to {host}:{port}")
        for w in insecure_warnings:
            print(f"!   {w}")
        print(f"!   Connected for certificate inspection only.")
        print()

    # Warn when SNI was dropped to make the connection work
    if "no SNI" in connected_label and sni:
        print()
        print(f"! WARNING: connected without SNI (Server Name Indication)")
        print(f"!   The server rejected the handshake when SNI={sni}")
        print(f"!   was included.  The certificate below may be the server's")
        print(f"!   default/fallback certificate, not the one for {sni}.")
        print()

    # --- Extract certificate chain ---
    pem_parts = []

    try:
        # Primary method: get the full chain as sent by the server
        chain = ssock._sslobj.get_unverified_chain()
        if chain:
            for cert_obj in chain:
                pem = cert_obj.public_bytes(_ssl.ENCODING_PEM)
                if isinstance(pem, str):
                    pem = pem.encode("ascii")
                pem_parts.append(pem)
            if verbose >= 1:
                print(f"  # Received {len(chain)} certificate(s) in chain")
    except (AttributeError, TypeError):
        # Fallback: leaf certificate only
        der = ssock.getpeercert(binary_form=True)
        if der:
            b64 = base64.b64encode(der).decode("ascii")
            lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
            pem = (
                b"-----BEGIN CERTIFICATE-----\n"
                + "\n".join(lines).encode() + b"\n"
                + b"-----END CERTIFICATE-----\n"
            )
            pem_parts.append(pem)
            if verbose >= 1:
                print(f"  # Received 1 certificate (leaf only; "
                      f"upgrade to Python 3.13+ for full chain)")

    ssock.close()
    sock.close()

    if not pem_parts:
        raise ConnectionError(f"No certificates received from {host}:{port}")

    pem_data = b"\n".join(pem_parts)
    return pem_data, len(pem_parts)


# ---------------------------------------------------------------------------
#  Library entry point
# ---------------------------------------------------------------------------

def ssl_grep(
    target,                         # str: host, host:port, URL,
                                    #   or "--help", "-h", "--version", "-V"
    level=1,                        # 0-4, or "summary_0".."summary_4", or "full"
    verbose=0,                      # 0=quiet, 1+=diagnostics (stacks with $VERBOSE env)
    show_pub=False,                 # show public key details
    show_fp=False,                  # show fingerprints
    save_file=False,                # save cert(s) as PEM
    first_only=False,               # show only first cert (like f_zero)
    cert_index=None,                # show only cert N (int), e.g. cert_index=0 same as first_only
    verify_chain=False,             # run chain verification
    weakness_scan=False,            # run weakness scan against policy config
    weak_configs=None,              # list of additional weak.conf paths (or None)
    timeout=_CONNECT_TIMEOUT,       # TCP/TLS timeout in seconds
    no_proxy=False,                 # bypass https_proxy / http_proxy
    no_verify_ssl=False,            # skip SSL certificate verification (already default for inspection)
    output=sys.stdout,              # file-like or None
) -> str:
    """Connect to a TLS endpoint and display its certificate chain.

    Args:
        target:    Hostname, host:port, or URL (e.g. "https://example.com").
                   Also accepts "--help"/"-h" or "--version"/"-V".
        level:     Summary level 0-4 (int or str), or "full".
        verbose:   Verbosity (0=normal, 1+=diagnostics). Stacks with $VERBOSE env.
        show_pub:  Include public key details.
        show_fp:   Include fingerprints.
        save_file: Write each cert as PEM to current directory.
        first_only: Show only the first certificate (cert 0), like f_zero.
        cert_index: Show only item N (0-based). Overrides first_only.
        verify_chain: Run chain verification on 2+ certificates.
        weakness_scan: Run weakness scan against policy config.
        weak_configs:  Additional config file paths for weakness rules.
        timeout:   TCP connect and TLS handshake timeout (seconds).
        output:    File-like for printed output, or None = return only.

    Returns:
        Formatted certificate text on success, or error message on failure.
        Empty string only for --help / --version with output=None suppressed.

    Connection errors (ConnectionError, ssl.SSLError, socket.timeout) are
    handled internally — the error is printed to stderr and returned as a
    string prefixed with "- Failed:".  This keeps the function usable as a
    fire-and-forget subroutine without requiring try/except in the caller.
    """
    # -- Handle informational requests --
    if isinstance(target, str) and target in ("--help", "-h"):
        text = _help_text()
        if output is not None:
            print(text, file=output)
        return text

    if isinstance(target, str) and target in ("--version", "-V"):
        text = _version_text()
        if output is not None:
            print(text, file=output)
        return text

    # -- Stack $VERBOSE env with verbose parameter --
    env_verbose = os.environ.get("VERBOSE", "")
    if env_verbose.strip().isdigit():
        verbose += int(env_verbose.strip())

    # -- Parse target --
    host, port = parse_target(target)
    if not host:
        raise ValueError(f"Invalid target: {target!r}")

    # -- Connect and get certificates --
    try:
        pem_data, cert_count = get_server_certificates(
            host, port, timeout=timeout, verbose=verbose,
            no_proxy=no_proxy, no_verify_ssl=no_verify_ssl
        )
    except ConnectionError as e:
        msg = f"\n- Failed: {e}\n"
        print(msg, file=sys.stderr)
        return msg.strip()
    except ssl.SSLError as e:
        detail = e.args[0] if e.args else str(e)
        msg = f"\n- Failed: TLS error: {detail}\n"
        print(msg, file=sys.stderr)
        return msg.strip()

    # Pass PEM data to cert_grep library
    result = cert_grep(
        source=pem_data,
        level=level,
        verbose=verbose,
        show_pub=show_pub,
        show_fp=show_fp,
        save_file=save_file,
        first_only=first_only,
        cert_index=cert_index,
        force_type="x509",
        force_encoding="pem",
        verify_chain=verify_chain,
        weakness_scan=weakness_scan,
        weak_configs=weak_configs,
        output=output,
    )
    return result


# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------

def _help_text() -> str:
    return f"""ssl-grep.py v{__version__}  (cert-grep.py v{_cert_grep_version})

Usage:
  $ ssl-grep.py  <host_or_url> [<host_or_url>...]  [options...]

Options (case-insensitive, order-independent):
  0 | summary_0      Short: Issuer CN, Subject CN, Serial, Validity
  1 | summary_1      Default: Algorithms, DN breakdown, Validity, Key extensions
  2 | summary_2      Verbose: All extensions + fingerprints
  3 | summary_3      Near-full: Full text, hex lines stripped
  4 | full           Full OpenSSL-style text output

  pub               Show public key details (RSA/ECC/EdDSA)
  fp                Show fingerprints (MD5, SHA-1, SHA-256)
  ver               Verify certificate chain
  weak              Scan for cryptographic weaknesses (policy-driven)
  file              Save decoded certificate(s) to current directory
  c0                Show only the first certificate (cert 0)
  cN                Show only item N (e.g. c0, c1, c42)

  -v, --verbose     Verbose diagnostics (stacks: -v -v for more)
  -V, --version     Show version and exit
  -h, --help        Show this help

  WEAK=<path>       Load additional weakness policy file(s)
                    Default: configs/weak.conf (relative to cert-grep.py)

Target formats (all equivalent for port 443):
  $ ssl-grep.py  https://example.com
  $ ssl-grep.py  https://example.com/path/to/page
  $ ssl-grep.py  example.com
  $ ssl-grep.py  example.com:443
  $ ssl-grep.py  example.com:8443        # non-standard port

Examples:
  $ ssl-grep.py  https://example.com
  $ ssl-grep.py  https://example.com  summary_0
  $ ssl-grep.py  https://example.com  summary_0  pub
  $ ssl-grep.py  https://example.com  2  fp
  $ ssl-grep.py  example.com:443  full
  $ ssl-grep.py  example.com  ver        # fetch + verify chain
  $ ssl-grep.py  example.com  weak       # scan for weaknesses
  $ ssl-grep.py  example.com  ver weak   # both: verify + weakness scan
  $ ssl-grep.py  example.com  file       # save PEM files

Multiple URLs (options apply to all targets):
  $ ssl-grep.py  https://one.com  https://two.com  summary_0
  $ ssl-grep.py  summary_0  fp  https://one.com  https://two.com

Options:
  -no-proxy         Bypass $https_proxy / $http_proxy for direct connection
  -no-verify-ssl    Skip SSL verification (already off by default for inspection)

Environment variables:
  $CERTGREP_SUMMARY/CNUM/FP/PUB   See cert-grep --help for all CERTGREP_ variables
  $SSLGREP_PROXY=no               Same as -no-proxy
  $SSLGREP_VERIFY_SSL=no          Same as -no-verify-ssl
  $SSLGREP_TIMEOUT                Override connect timeout (seconds, default: {_CONNECT_TIMEOUT})
  $SSLGREP_NO_TIMEOUT             Suppress timeout protection
  $VERBOSE                        Verbosity level (0-2), like -v
  $https_proxy / $http_proxy      HTTP CONNECT proxy (e.g. http://proxy:8080/)

See also:
  $ cert-grep.py --help
  Source:  https://gitlab.com/umi-ch/cert-grep
  Web UI: https://gitlab.com/umi-ch/cert-grep (web/ directory)
"""


def _version_text() -> str:
    return (
        f"\n  ssl-grep.py:   v{__version__}\n"
        f"  cert-grep.py:  v{_cert_grep_version}\n"
        f"  python:        v{sys.version.split()[0]}\n"
        f"  ssl:           {ssl.OPENSSL_VERSION}\n"
    )


def ssl_grep_main():
    """Command-line interface — parses sys.argv and calls ssl_grep()."""
    all_args = sys.argv[1:]

    if not all_args or "-h" in all_args or "--help" in all_args:
        ssl_grep("--help")
        sys.exit(2)

    if "-V" in all_args or "--version" in all_args:
        ssl_grep("--version")
        sys.exit(2)

    # -- Parse arguments --
    level = 1
    show_pub = False
    show_fp = False
    save_file = False
    first_only = False
    cert_index = None
    verify_chain = False
    weakness_scan = False
    weak_configs = None   # None = not specified; [] = specified but empty
    targets = []
    verbose = 0
    no_proxy = False
    no_verify_ssl = False

    # -- Environment variable defaults (CLI args override these) --
    # Shared with cert-grep:
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
    _env_cnum = os.environ.get("CERTGREP_CNUM", "").strip()
    if _env_cnum:
        if _env_cnum.isdigit():
            _n = int(_env_cnum)
            if _n == 0:  first_only = True
            else:        cert_index = _n
        else:
            print(f"- Warning: CERTGREP_CNUM='{_env_cnum}' must be a non-negative integer, "
                  f"ignored", file=sys.stderr)
    _env_fp = os.environ.get("CERTGREP_FP", "").strip().lower()
    if _env_fp == "yes":  show_fp = True
    _env_pub = os.environ.get("CERTGREP_PUB", "").strip().lower()
    if _env_pub == "yes": show_pub = True
    # ssl-grep specific:
    if os.environ.get("SSLGREP_PROXY", "").strip().lower() == "no":
        no_proxy = True
    elif os.environ.get("SSLGREP_PROXY", "").strip() not in ("", "yes"):
        print(f"- Warning: SSLGREP_PROXY='{os.environ['SSLGREP_PROXY']}' — only 'yes' or 'no' supported, ignored",
              file=sys.stderr)
    if os.environ.get("SSLGREP_VERIFY_SSL", "").strip().lower() == "no":
        no_verify_ssl = True
    elif os.environ.get("SSLGREP_VERIFY_SSL", "").strip() not in ("", "yes"):
        print(f"- Warning: SSLGREP_VERIFY_SSL='{os.environ['SSLGREP_VERIFY_SSL']}' — only 'yes' or 'no' supported, ignored",
              file=sys.stderr)

    for arg in all_args:
        a = arg.lower()
        if   a in ("summary_0","summary0","0"):           level = 0
        elif a in ("summary_1","summary1","1","summary"): level = 1
        elif a in ("summary_2","summary2","2"):           level = 2
        elif a in ("summary_3","summary3","3"):           level = 3
        elif a in ("summary_4","summary4","4","full"):    level = 4

        elif a == "pub":                                  show_pub = True
        elif a == "fp":                                   show_fp = True
        elif a in ("file","preserve","x"):                save_file = True
        elif a == "c0":                                   first_only = True
        elif re.match(r"c\d+$", a):                       cert_index = int(a[1:])
        elif a in ("-v","--verbose"):                     verbose += 1
        elif a == "-no-proxy":                            no_proxy = True
        elif a == "-no-verify-ssl":                       no_verify_ssl = True
        elif a in ("ver","verify"):                      verify_chain = True
        elif a == "weak":                                 weakness_scan = True
        elif arg.upper().startswith("WEAK="):
            weakness_scan = True
            if weak_configs is None:
                weak_configs = []
            import glob as _glob
            for pattern in arg.split("=", 1)[1].split(","):
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
        else:
            targets.append(arg)

    if not targets:
        ssl_grep("--help")
        sys.exit(2)

    # -- Connect and display --
    multi = len(targets) > 1
    errors = 0
    try:
        for i, t in enumerate(targets):
            if multi:
                if i > 0:
                    print()
                print(f"# TARGET: {t}")
            try:
                result = ssl_grep(
                    target=t,
                    level=level,
                    verbose=verbose,
                    show_pub=show_pub,
                    show_fp=show_fp,
                    save_file=save_file,
                    first_only=first_only,
                    cert_index=cert_index,
                    verify_chain=verify_chain,
                    weakness_scan=weakness_scan,
                    weak_configs=weak_configs,
                    no_proxy=no_proxy,
                    no_verify_ssl=no_verify_ssl,
                )
                if result.startswith("- Failed:"):
                    errors += 1
            except ValueError as e:
                print(f"\n- Error: {e}\n", file=sys.stderr)
                errors += 1
    except KeyboardInterrupt:
        print("\n- Interrupted.\n", file=sys.stderr)
        sys.exit(130)

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    ssl_grep_main()
