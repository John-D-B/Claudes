#!/usr/bin/env python3
"""
ejbca-lifecycle-tool.py — EJBCA End Entity Lifecycle Management for K8s cert-manager

Addresses the split horizon problem between Kubernetes cert-manager and EJBCA
by providing listing, reporting, and cleanup capabilities for End Entities and
certificates that accumulate in EJBCA due to cert-manager renewals.

Commands:
  list     — List EE profiles, entities, and certificates at detail levels:
             -d1  EE Profile names + IDs
             -d2  + associated Certificate Profiles
             -d3  + EE usernames with cert counts (default)
             -d4  + full certificate tables per EE
  count    — Certificate count overview (global totals + per-EE breakdown)
  cleanup  — Revoke and/or delete orphaned End Entities.
             Defaults to dry-run; requires -commit for destructive actions.
  ping     — Verify REST API connectivity.

Authentication:
  Uses mTLS client certificate to authenticate with EJBCA REST API,
  matching the same authentication method used by the cert-manager issuer.

Requirements:
  Python 3.8+
  requests (pip install requests)
  kubectl on PATH (optional, for -k8s-compare; or set -kubectl / ELT_KUBECTL)

Reference:
  EJBCA REST API: https://docs.keyfactor.com/ejbca/latest/ejbca-rest-interface
  Companion doc:  X509-Certificate-Lifecycle-EJBCA-CertManager.md

This tool also serves as an onboarding aid for understanding EJBCA
end-entity and certificate structures.

Original software by John Buehrer
with AI pair-programming support by Anthropic Claude
"""

__version__ = "5.5.0"

import argparse
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Optional, Protocol
from urllib.parse import quote

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    print("ERROR: 'requests' library required. Install with: pip install requests",
          file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.WARNING)
log = logging.getLogger("ejbca-lifecycle")

# ---------------------------------------------------------------------------
# Backend abstraction — v4.0.0 SOAP-backend seam (Phase 5)
# ---------------------------------------------------------------------------
#
# EJBCA Community Edition does not ship the End Entity REST API ("Management
# REST API" in the vendor's edition matrix). To let ELT work against CE,
# v4.0.0 adds a SOAP backend that targets the SOAP Web Service (which CE
# does ship). See:
#   - Docs/ejbca-ce-rest-endentity-gap.md  (why this exists)
#   - Docs/ejbca-ce-soap-mapping.md        (REST → SOAP operation mapping)
#   - Docs/ejbca-ce-implementation-plan.md, Phase 5
#
# Design intent: the End Entity methods on EjbcaClient become dispatch
# points. When EjbcaClient._ee_backend is None (the default), they run their
# existing REST code unchanged — preserving byte-for-byte behaviour against
# EJBCA Enterprise. When _ee_backend is set (in CE mode, or via explicit
# --zeep flag), the method delegates to the backend instead.
#
# Status of this seam:
#   - 5.3 (this commit): Protocol declared, attribute initialised to None,
#         no dispatch logic wired. Behaviour is provably unchanged because
#         the attribute is never read.
#   - 5.4: EjbcaSoapBackend implements this Protocol against the SOAP WS.
#   - 5.5: dispatch wired into the six EE methods on EjbcaClient, plus
#         CLI flag / env var / auto-detect for backend selection.

class EndEntityBackend(Protocol):
    """End Entity operations contract for ELT's pluggable backends.

    Default implementation is the existing REST methods on EjbcaClient
    (implicit — used when EjbcaClient._ee_backend is None). The alternate
    implementation EjbcaSoapBackend (added in step 5.4) targets the SOAP
    Web Service, which ships in EJBCA Community Edition.
    """

    def search_end_entities(self, criteria: list[dict],
                            max_results: int = 100) -> list[dict]: ...

    def revoke_end_entity(self, ee_name: str,
                          reason: str = "CESSATION_OF_OPERATION") -> bool: ...

    def delete_end_entity(self, ee_name: str) -> bool: ...

    def get_end_entity(self, ee_name: str) -> Optional[dict]: ...

    def get_end_entity_profile(self, profile_name: str) -> Optional[dict]: ...

    def get_authorized_profiles(self) -> Optional[dict]: ...


# ---------------------------------------------------------------------------
# SOAP backend implementation — Phase 5.4
# ---------------------------------------------------------------------------
#
# Used when targeting EJBCA Community Edition, which doesn't ship the End
# Entity REST API. Implements the EndEntityBackend Protocol above using
# EJBCA's SOAP Web Service at /ejbca/ejbcaws/ejbcaws. The same admin client
# cert + key + CA chain that ELT already uses for REST works for SOAP — the
# mTLS surface is identical.
#
# zeep is imported lazily inside __init__ so that ELT can still start (and
# run REST against EE) without zeep installed. Only users who switch to
# SOAP mode need zeep on their system. See Docs/ejbca-ce-soap-mapping.md
# for the REST → SOAP operation correspondence.

class EjbcaSoapBackend:
    """SOAP-based End Entity backend for EJBCA Community Edition.

    Conforms to the EndEntityBackend Protocol; instances may be assigned to
    EjbcaClient._ee_backend (5.5 wires the dispatch).
    """

    # EJBCA UserDataConstants — status name ↔ integer code
    STATUS_TO_INT = {
        "NEW": 10, "FAILED": 11, "INITIALIZED": 20,
        "INPROCESS": 30, "GENERATED": 40, "REVOKED": 50,
        "HISTORICAL": 60, "KEYRECOVERY": 70,
    }
    INT_TO_STATUS = {v: k for k, v in STATUS_TO_INT.items()}

    # EJBCA UserMatch.MATCH_WITH_* — REST property name → SOAP matchwith int
    PROPERTY_TO_MATCHWITH = {
        "USERNAME":           0,
        "EMAIL":              1,
        "STATUS":             2,
        "END_ENTITY_PROFILE": 3,
        "CERTIFICATE_PROFILE":4,
        "CA":                 5,
        "TOKEN":              6,
        "DN":                 7,
        "SUBJECT_ALT_NAME":   8,
    }

    # EJBCA UserMatch.MATCH_TYPE_* — REST operation → SOAP matchtype int
    OPERATION_TO_MATCHTYPE = {
        "EQUAL":       0,
        "BEGINSWITH":  1,
        "CONTAINS":    2,
        "LIKE":        2,
    }

    # RFC 5280 revocation reasons — REST string ↔ SOAP int
    REVOCATION_REASON_TO_INT = {
        "NOT_REVOKED":            -1,
        "UNSPECIFIED":             0,
        "KEY_COMPROMISE":          1,
        "CA_COMPROMISE":           2,
        "AFFILIATION_CHANGED":     3,
        "SUPERSEDED":              4,
        "CESSATION_OF_OPERATION":  5,
        "CERTIFICATE_HOLD":        6,
        "REMOVE_FROM_CRL":         8,
        "PRIVILEGES_WITHDRAWN":    9,
        "AA_COMPROMISE":          10,
    }

    # Reverse map from REST property → key used in REST-shape result dicts
    # (used for client-side post-filtering when there are multiple criteria)
    PROPERTY_TO_RESULT_KEY = {
        "USERNAME":            "username",
        "EMAIL":               "email",
        "STATUS":              "status",
        "END_ENTITY_PROFILE":  "end_entity_profile_name",
        "CERTIFICATE_PROFILE": "certificate_profile_name",
        "CA":                  "ca_name",
        "DN":                  "dn",
        "SUBJECT_ALT_NAME":    "subject_alt_name",
    }

    def __init__(self, host: str, client_cert: str, client_key: str,
                 ca_cert: Optional[str] = None, port: int = 443,
                 verify_ssl: bool = True, no_proxy: bool = False,
                 wsdl: Optional[str] = None):
        # Lazy zeep import — keep ELT startable without zeep on REST-only setups.
        try:
            import zeep
            from zeep.transports import Transport
        except ImportError as e:
            raise ImportError(
                "EjbcaSoapBackend requires the 'zeep' package. Install via:\n"
                "    pip install zeep\n"
                "Only needed when ELT runs against EJBCA Community Edition "
                "(or with --zeep). EE users on REST don't need it."
            ) from e

        # Build an mTLS-configured requests Session for zeep's Transport.
        session = requests.Session()
        session.cert = (client_cert, client_key)
        if no_proxy:
            session.proxies = {"http": "", "https": ""}
            session.trust_env = False
        if ca_cert:
            session.verify = ca_cert
        elif not verify_ssl:
            session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Resolve WSDL source: explicit > local cached file > live URL.
        if wsdl is None:
            # realpath() (not abspath) so the lookup follows symlinks —
            # ELT may be invoked via a bin/-style symlink (e.g.
            # John-D-B/Claudes/2026-06-01.EJBCA-tools/bin/) and abspath
            # would return the symlink's parent (bin/), missing the
            # sibling wsdl/ dir that lives next to the real source file.
            local = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 "wsdl", "ejbca-ws.wsdl")
            wsdl = local if os.path.exists(local) else \
                   f"https://{host}:{port}/ejbca/ejbcaws/ejbcaws?wsdl"
        log.debug(f"EjbcaSoapBackend: WSDL source = {wsdl}")

        transport = Transport(session=session)
        self._zeep = zeep.Client(wsdl, transport=transport)
        self._svc = self._zeep.service

        # The WSDL's <soap:address> field points at the container's internal
        # hostname (e.g. 32af9e1ba61a:443). Override to whatever the caller
        # actually reached us at, so SOAP requests go to the real endpoint.
        endpoint = f"https://{host}:{port}/ejbca/ejbcaws/ejbcaws"
        self._svc._binding_options["address"] = endpoint

        # Profile name → ID cache (populated by get_authorized_profiles).
        # SOAP getProfile takes an ID, not a name, so we need this mapping.
        self._profile_id_cache: Optional[dict] = None

    # --- helpers --------------------------------------------------------

    def _userdatavows_to_dict(self, vows) -> dict:
        """Map a SOAP userDataVOWS object to ELT's REST-style dict shape."""
        status_int = getattr(vows, "status", None)
        return {
            "username":         getattr(vows, "username", "") or "",
            "dn":               getattr(vows, "subjectDN", "") or "",
            "subject_alt_name": getattr(vows, "subjectAltName", "") or "",
            "email":            getattr(vows, "email", "") or "",
            "status":           self.INT_TO_STATUS.get(status_int, str(status_int)),
            "token":            getattr(vows, "tokenType", "") or "",
            "extension_data":   {},
            # Extra profile metadata that SOAP gives us inline — REST's End
            # Entity search omits these (see fix request 11), so callers
            # that worked around the gap will get the fields filled in.
            "end_entity_profile_name":  getattr(vows, "endEntityProfileName",  "") or "",
            "certificate_profile_name": getattr(vows, "certificateProfileName", "") or "",
            "ca_name":                  getattr(vows, "caName", "") or "",
        }

    def _build_user_match(self, criterion: dict) -> Optional[dict]:
        """Translate one REST search criterion to a SOAP userMatch dict."""
        prop = criterion.get("property", "")
        op = criterion.get("operation", "EQUAL")
        value = criterion.get("value", "")

        match_with = self.PROPERTY_TO_MATCHWITH.get(prop)
        match_type = self.OPERATION_TO_MATCHTYPE.get(op, 0)
        if match_with is None:
            log.error(f"SOAP search: unsupported property {prop!r}")
            return None

        # STATUS comes in as a string name ("NEW", "REVOKED", ...) at the
        # REST layer; SOAP wants the integer code.
        if prop == "STATUS" and isinstance(value, str):
            mapped = self.STATUS_TO_INT.get(value.upper())
            if mapped is not None:
                value = str(mapped)

        return {"matchwith": match_with, "matchtype": match_type,
                "matchvalue": str(value)}

    def _post_filter(self, results: list[dict],
                     criteria: list[dict]) -> list[dict]:
        """Apply additional criteria client-side after SOAP findUser."""
        out = results
        for crit in criteria:
            key = self.PROPERTY_TO_RESULT_KEY.get(crit.get("property", ""))
            if key is None:
                log.warning(f"SOAP post-filter: skipping unknown property "
                            f"{crit.get('property')!r}")
                continue
            val = crit.get("value", "")
            op = crit.get("operation", "EQUAL")
            if op == "EQUAL":
                out = [r for r in out if r.get(key) == val]
            elif op == "BEGINSWITH":
                out = [r for r in out if str(r.get(key, "")).startswith(val)]
            elif op in ("CONTAINS", "LIKE"):
                out = [r for r in out if val in str(r.get(key, ""))]
        return out

    # --- EndEntityBackend Protocol implementation -----------------------

    def search_end_entities(self, criteria: list[dict],
                            max_results: int = 100) -> Optional[list[dict]]:
        """SOAP findUser equivalent of REST /v[12]/endentity/search.

        Uses the first criterion for the SOAP call; remaining criteria are
        applied client-side as post-filters. Single-criterion search (the
        common ELT case) goes through with zero post-filtering overhead.
        """
        if not criteria:
            # SOAP requires at least one criterion. Default to a permissive
            # match so callers asking for "everything" get something useful.
            criteria = [{"property": "STATUS", "value": "GENERATED",
                         "operation": "EQUAL"}]
            log.warning("SOAP search needs a criterion; defaulting to "
                        "STATUS=GENERATED. Caller should pass criteria.")

        user_match = self._build_user_match(criteria[0])
        if user_match is None:
            return None

        try:
            raw = self._svc.findUser(user_match) or []
        except Exception as e:
            log.error(f"SOAP findUser failed: {e}")
            return None

        results = [self._userdatavows_to_dict(r) for r in raw]
        if len(criteria) > 1:
            results = self._post_filter(results, criteria[1:])
        return results[:max_results]

    def revoke_end_entity(self, ee_name: str,
                          reason: str = "CESSATION_OF_OPERATION") -> bool:
        """SOAP revokeUser with deleteUser=False (revoke only)."""
        reason_int = self.REVOCATION_REASON_TO_INT.get(reason)
        if reason_int is None:
            log.error(f"Invalid revocation reason: {reason}")
            return False
        try:
            self._svc.revokeUser(ee_name, reason_int, False)
            log.info(f"Revoked end entity (SOAP): {ee_name} (reason: {reason})")
            return True
        except Exception as e:
            log.error(f"SOAP revokeUser failed for {ee_name}: {e}")
            return False

    def delete_end_entity(self, ee_name: str) -> bool:
        """SOAP revokeUser with deleteUser=True (revoke + delete in one call).

        Per the 5.2 mapping: there is no separate delete-EE SOAP op; revoke
        with the deleteUser boolean is EJBCA's traditional pattern. Default
        reason is CESSATION_OF_OPERATION matching ELT's REST default.
        """
        try:
            reason_int = self.REVOCATION_REASON_TO_INT["CESSATION_OF_OPERATION"]
            self._svc.revokeUser(ee_name, reason_int, True)
            log.info(f"Deleted end entity (SOAP, revokeUser deleteUser=True): "
                     f"{ee_name}")
            return True
        except Exception as e:
            log.error(f"SOAP delete (via revokeUser) failed for {ee_name}: {e}")
            return False

    def get_end_entity(self, ee_name: str) -> Optional[dict]:
        """SOAP findUser with USERNAME=ee_name. Unlike REST, SOAP supports
        direct username lookup — so no STATUS-iteration workaround is needed.
        """
        user_match = {
            "matchwith":  self.PROPERTY_TO_MATCHWITH["USERNAME"],
            "matchtype":  self.OPERATION_TO_MATCHTYPE["EQUAL"],
            "matchvalue": ee_name,
        }
        try:
            raw = self._svc.findUser(user_match) or []
        except Exception as e:
            log.error(f"SOAP findUser (single) failed for {ee_name}: {e}")
            return None
        for r in raw:
            if getattr(r, "username", "") == ee_name:
                return self._userdatavows_to_dict(r)
        return None

    def get_authorized_profiles(self) -> Optional[dict]:
        """SOAP getAuthorizedEndEntityProfiles — returns {name: id_str}.

        Result is cached on this instance for subsequent get_end_entity_profile
        lookups (which need the profile ID, not the name).
        """
        try:
            raw = self._svc.getAuthorizedEndEntityProfiles() or []
        except Exception as e:
            log.error(f"SOAP getAuthorizedEndEntityProfiles failed: {e}")
            return None
        profiles = {}
        for item in raw:
            name = getattr(item, "name", "")
            ident = getattr(item, "id", "")
            if name and ident is not None:
                profiles[str(name)] = str(ident)
        self._profile_id_cache = profiles
        return profiles

    def get_end_entity_profile(self, profile_name: str) -> Optional[dict]:
        """SOAP getProfile equivalent of REST /v2/endentity/profile/{name}.

        SOAP getProfile takes (id, type), not the name. We resolve the name
        to an ID via the cached authorized-profiles map. The returned profile
        is base64-encoded XML; we wrap it in a dict so callers see a stable
        shape — actual XML parsing is left to consumers that need specific
        profile fields.
        """
        if self._profile_id_cache is None:
            self.get_authorized_profiles()
        if not self._profile_id_cache:
            log.error("SOAP get_end_entity_profile: no authorized profiles "
                      "available (lookup failed or empty)")
            return None
        profile_id = self._profile_id_cache.get(profile_name)
        if profile_id is None:
            log.debug(f"SOAP get_end_entity_profile: name not found in "
                      f"authorized profiles: {profile_name!r}")
            return None
        try:
            xml_payload = self._svc.getProfile(int(profile_id), "eep")
        except Exception as e:
            log.error(f"SOAP getProfile failed for {profile_name}: {e}")
            return None
        return {
            "profile_name": profile_name,
            "profile_id":   profile_id,
            "profile_xml":  xml_payload,
        }


# ---------------------------------------------------------------------------
# EJBCA REST API Client
# ---------------------------------------------------------------------------

class EjbcaClient:
    """Minimal EJBCA REST API client using mTLS authentication."""

    # Valid RFC 5280 revocation reasons accepted by EJBCA
    REVOCATION_REASONS = [
        "NOT_REVOKED", "UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE",
        "AFFILIATION_CHANGED", "SUPERSEDED", "CESSATION_OF_OPERATION",
        "CERTIFICATE_HOLD", "REMOVE_FROM_CRL", "PRIVILEGES_WITHDRAWN",
        "AA_COMPROMISE",
    ]

    def __init__(self, host: str, client_cert: str, client_key: str,
                 ca_cert: Optional[str] = None, port: int = 443,
                 verify_ssl: bool = True, no_proxy: bool = False):
        self.base_url = f"https://{host}:{port}/ejbca/ejbca-rest-api"
        self.session = requests.Session()
        self.session.cert = (client_cert, client_key)
        # Optionally bypass proxy for direct mTLS connections
        if no_proxy:
            self.session.proxies = {"http": "", "https": ""}
            self.session.trust_env = False
        if ca_cert:
            self.session.verify = ca_cert
        elif not verify_ssl:
            self.session.verify = False
            # Suppress InsecureRequestWarning for dev/test usage
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        # v4.0.0 SOAP-backend seam — see "Backend abstraction" section above.
        # When None (default), the six End Entity methods on this class run
        # their existing REST code unchanged. Set explicitly (or by 5.5's
        # auto-detect) to switch to SOAP. 5.5 will wire the dispatch.
        self._ee_backend: Optional["EndEntityBackend"] = None

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _request(self, method: str, path: str, log_errors: bool = True,
                 **kwargs) -> requests.Response:
        url = self._url(path)
        log.debug(f"{method.upper()} {url}")
        resp = self.session.request(method, url, **kwargs)
        if resp.status_code >= 400 and log_errors:
            log.error(f"EJBCA API error: {resp.status_code} — {resp.text[:500]}")
        elif resp.status_code >= 400:
            log.debug(f"EJBCA API returned {resp.status_code}: {resp.text[:200]}")
        return resp

    # --- End Entity operations ---

    def search_end_entities_v2(self, criteria: list[dict],
                                max_results: int = 100) -> list[dict]:
        """
        Search for End Entities using POST /v2/endentity/search.
        Returns a list of end entity records.

        Note: v2 requires sort_operation and current_page fields.
        Note: END_ENTITY_PROFILE and CERTIFICATE_PROFILE criteria require
              numeric database identifiers, not user-given names.
              Use get_end_entity_profile() to resolve name → ID.

        Criteria example:
          [{"property": "STATUS", "value": "NEW",
            "operation": "EQUAL"}]
        """
        payload = {
            "max_number_of_results": max_results,
            "current_page": 1,
            "criteria": criteria,
            "sort_operation": {
                "property": "USERNAME",
                "operation": "ASC",
            },
        }
        resp = self._request("POST", "/v2/endentity/search", json=payload)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("end_entities", [])
        log.warning(f"End entity search (v2) returned status {resp.status_code}")
        return None  # None = failed; [] = success with no results

    def search_end_entities_v1(self, criteria: list[dict],
                                max_results: int = 100) -> list[dict]:
        """
        Fallback: Search using POST /v1/endentity/search.
        Some EJBCA versions may only support v1.
        """
        payload = {
            "max_number_of_results": max_results,
            "criteria": criteria,
        }
        resp = self._request("POST", "/v1/endentity/search", json=payload)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("end_entities", [])
        log.warning(f"End entity search (v1) returned status {resp.status_code}")
        return []

    def search_end_entities(self, criteria: list[dict],
                             max_results: int = 100) -> list[dict]:
        """Try v2 first, fall back to v1. Empty results from v2 are valid."""
        if self._ee_backend is not None:
            return self._ee_backend.search_end_entities(criteria, max_results)
        results = self.search_end_entities_v2(criteria, max_results)
        if results is not None:
            return results
        log.info("v2 search failed; trying v1 endpoint")
        return self.search_end_entities_v1(criteria, max_results)

    def _search_v2_quiet(self, criteria: list[dict],
                         max_results: int = 100) -> Optional[list[dict]]:
        """v2 search that logs failures at DEBUG level (for iteration use).

        v5.0.0 fix 1: respect the EE backend dispatch shim. The non-quiet
        ``search_end_entities`` already routes through ``_ee_backend`` when
        attached, but ``search_all_end_entities`` and friends call the
        quiet variants directly — so without this shim, CE/SOAP runs
        unconditionally hit REST ``/v[12]/endentity/search`` (which is
        EE-only and 404s), causing every per-profile and per-EE listing
        to come back empty. Symptom: ``list3`` / ``list4`` / ``count``
        print "No End Entities found" against a CE stack that has plenty.
        """
        if self._ee_backend is not None:
            return self._ee_backend.search_end_entities(criteria, max_results)
        payload = {
            "max_number_of_results": max_results,
            "current_page": 1,
            "criteria": criteria,
            "sort_operation": {
                "property": "USERNAME",
                "operation": "ASC",
            },
        }
        resp = self._request("POST", "/v2/endentity/search",
                             log_errors=False, json=payload)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("end_entities", [])
        log.debug(f"v2 search returned {resp.status_code}")
        return None

    def _search_v1_quiet(self, criteria: list[dict],
                         max_results: int = 100) -> list[dict]:
        """v1 search that logs failures at DEBUG level.

        v5.0.0 fix 1: when an EE backend is attached (CE/SOAP), v1 is the
        wrong path; the v2 quiet variant already routed the call through
        the backend, so this just returns []. Returning [] here also keeps
        the existing fallback ladder in ``search_all_end_entities`` from
        re-issuing the same backend call twice.
        """
        if self._ee_backend is not None:
            return []
        payload = {
            "max_number_of_results": max_results,
            "criteria": criteria,
        }
        resp = self._request("POST", "/v1/endentity/search",
                             log_errors=False, json=payload)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("end_entities", [])
        log.debug(f"v1 search returned {resp.status_code}")
        return []

    def search_all_end_entities(self, max_results: int = 100,
                                 status_filter: Optional[str] = None,
                                 profile_name: Optional[str] = None,
                                 ) -> list[dict]:
        """Search all End Entities, optionally filtered by EE profile name.

        When profile_name is supplied, uses the END_ENTITY_PROFILE criterion
        on the v2 endpoint (single query, server-side filter). Confirmed to
        work with profile names — NOT numeric IDs — across EJBCA 9.2.3–9.4.2.
        Note: v1 silently returns 0 for this criterion; v2 is used exclusively.

        When profile_name is not supplied, falls back to iterating all STATUS
        values (v2 with v1 fallback), which is the only reliable approach for
        fetching all entities regardless of profile.

        Args:
            max_results:   Max results per query.
            status_filter: If set, restrict STATUS iteration to one value.
            profile_name:  If set, use END_ENTITY_PROFILE criterion (v2 only).

        Returns:
            List of end entity dicts.
        """
        if profile_name:
            # Fast path: single v2 query with profile name criterion
            criteria = [{"property": "END_ENTITY_PROFILE",
                          "value": profile_name,
                          "operation": "EQUAL"}]
            if status_filter:
                criteria.append({"property": "STATUS",
                                  "value": status_filter,
                                  "operation": "EQUAL"})
            batch = self._search_v2_quiet(criteria, max_results)
            if batch is not None:
                log.info(f"  Profile {profile_name!r}: found {len(batch)}")
                return batch
            log.debug("END_ENTITY_PROFILE criterion failed on v2; "
                      "falling back to STATUS iteration")

        # Slow path: iterate all STATUS values
        if status_filter:
            statuses = [status_filter]
        else:
            statuses = [
                "NEW", "GENERATED", "INITIALIZED", "REVOKED",
                "KEYRECOVERY", "HISTORICAL", "FAILED", "INPROCESS",
            ]

        all_entities = []
        for status in statuses:
            criteria = [{
                "property": "STATUS",
                "value": status,
                "operation": "EQUAL",
            }]
            batch = self._search_v2_quiet(criteria, max_results)
            if batch is None:
                batch = self._search_v1_quiet(criteria, max_results)
            if batch:
                log.info(f"  Status {status}: found {len(batch)}")
                all_entities.extend(batch)
            else:
                log.debug(f"  Status {status}: 0")

        return all_entities

    def get_end_entity_status(self) -> Optional[dict]:
        """GET /v2/endentity/status — check if endpoint is available."""
        resp = self._request("GET", "/v2/endentity/status")
        if resp.status_code == 200:
            return resp.json()
        return None

    def get_certificate_count(self, is_active: Optional[bool] = None
                              ) -> Optional[int]:
        """GET /v2/certificate/count — total certificate count.

        is_active: True for active only, False for inactive, None for all.
        Returns count, or -403 for permission denied, or None for error.
        """
        params = "ignoreerrors=true&defaults=true&externalcas=true"
        if is_active is not None:
            params += f"&isActive={'true' if is_active else 'false'}"
        resp = self._request("GET", f"/v2/certificate/count?{params}",
                             log_errors=False)
        if resp.status_code == 200:
            return resp.json().get("count")
        if resp.status_code == 403:
            log.debug(f"Certificate count endpoint returned 403 (access denied)")
            return -403
        log.debug(f"Certificate count endpoint returned {resp.status_code}")
        return None

    def revoke_end_entity(self, ee_name: str,
                          reason: str = "CESSATION_OF_OPERATION") -> bool:
        """
        PUT /v1/endentity/{endentity_name}/revoke
        Revokes ALL certificates associated with the End Entity.
        """
        if self._ee_backend is not None:
            return self._ee_backend.revoke_end_entity(ee_name, reason)
        if reason not in self.REVOCATION_REASONS:
            log.error(f"Invalid revocation reason: {reason}")
            return False
        ee_encoded = quote(ee_name, safe="")
        log.debug(f"Revoking EE: PUT /v1/endentity/{ee_encoded}/revoke"
                  f"?reason={reason}")
        resp = self._request("PUT",
                             f"/v1/endentity/{ee_encoded}/revoke",
                             params={"reason": reason})
        if resp.status_code in (200, 204):
            log.info(f"Revoked end entity: {ee_name} (reason: {reason})")
            return True
        body = ""
        try:
            body = resp.json().get("error_message", resp.text[:300])
        except Exception:
            body = resp.text[:300]
        log.error(f"EJBCA API error: {resp.status_code} — {body}")
        log.error(f"Failed to revoke {ee_name}: {resp.status_code}")
        return False

    def delete_end_entity(self, ee_name: str) -> bool:
        """
        DELETE /v1/endentity/{endentity_name}
        Deletes the End Entity record. Certificates may remain in the database.
        """
        if self._ee_backend is not None:
            return self._ee_backend.delete_end_entity(ee_name)
        ee_encoded = quote(ee_name, safe="")
        log.debug(f"Deleting EE: DELETE /v1/endentity/{ee_encoded}")
        resp = self._request("DELETE", f"/v1/endentity/{ee_encoded}")
        if resp.status_code in (200, 204):
            log.info(f"Deleted end entity: {ee_name}")
            return True
        body = ""
        try:
            body = resp.json().get("error_message", resp.text[:300])
        except Exception:
            body = resp.text[:300]
        log.error(f"EJBCA API error: {resp.status_code} — {body}")
        log.error(f"Failed to delete {ee_name}: {resp.status_code}")
        return False

    def get_end_entity(self, ee_name: str) -> Optional[dict]:
        """
        Fetch a single EE record by exact username match.
        EJBCA has no GET-by-username endpoint and USERNAME is not a valid
        search criterion, so we iterate over all STATUS values (quietly)
        and scan — same approach as search_all_end_entities().
        Returns the EE dict if found, None if deleted / never existed.
        """
        if self._ee_backend is not None:
            return self._ee_backend.get_end_entity(ee_name)
        for status in ("NEW", "GENERATED", "INITIALIZED", "REVOKED",
                       "KEYRECOVERY", "HISTORICAL", "FAILED", "INPROCESS"):
            criteria = [{"property": "STATUS", "value": status,
                          "operation": "EQUAL"}]
            batch = self._search_v2_quiet(criteria, max_results=10000)
            if batch is None:
                batch = self._search_v1_quiet(criteria, max_results=10000)
            for ee in (batch or []):
                if ee.get("username", "") == ee_name:
                    return ee
        log.debug(f"get_end_entity: no EE found for username {ee_name!r}")
        return None

    def search_certs_by_serial(self, serial: str,
                               max_results: int = 10) -> list[dict]:
        """
        Search certificates directly by serial number via the cert search API.
        Serial is normalised (colons stripped, lowercase) before search.
        Returns list of matching cert dicts (exact serial match).
        """
        serial_clean = serial.replace(":", "").lower()
        certs = self.search_certificates_v2(
            criteria=[{"property": "QUERY",
                        "value": serial_clean,
                        "operation": "LIKE"}],
            max_results=max_results,
        )
        # Filter to exact match in case QUERY is fuzzy
        return [c for c in certs
                if c.get("serialNumber", "").replace(":", "").lower()
                   == serial_clean]

    def revoke_certificate(self, issuer_dn: str, serial_hex: str,
                           reason: str = "SUPERSEDED") -> bool:
        """
        PUT /v1/certificate/{issuer_dn}/{serial}/revoke?reason=REASON
        Revokes a single certificate by issuer DN and serial number.
        """
        if reason not in self.REVOCATION_REASONS:
            log.error(f"Invalid revocation reason: {reason}")
            return False
        # Serial: strip colons for API
        serial_clean = serial_hex.replace(":", "").lower()
        issuer_encoded = quote(issuer_dn, safe="")
        resp = self._request(
            "PUT",
            f"/v1/certificate/{issuer_encoded}/{serial_clean}/revoke",
            params={"reason": reason})
        if resp.status_code in (200, 204):
            log.info(f"Revoked certificate: serial={serial_hex[:20]}... "
                     f"(reason: {reason})")
            return True
        body = ""
        try:
            body = resp.json().get("error_message", resp.text[:200])
        except Exception:
            body = resp.text[:200]
        log.error(f"Failed to revoke cert serial={serial_hex[:20]}...: "
                  f"{resp.status_code} {body}")
        return False

    # --- Certificate search (v2, with profile enrichment) ---

    def search_certificates_v2(self, criteria: list[dict],
                                max_results: int = 500) -> list[dict]:
        """POST /v2/certificate/search — Search for certificates.

        Uses the v2 endpoint which returns richer data per certificate
        including endEntityProfile, endEntityProfileId, and
        certificateProfile — fields that the EE search endpoint omits.

        Note: the v2 endpoint requires 'pagination' and 'sort' fields in
        the request body; without them it returns counts but no data.
        Uses ?ignoreerrors=true&defaults=true query params.
        """
        all_certs = []
        page = 1
        page_size = min(max_results, 500)

        while len(all_certs) < max_results:
            payload = {
                "pagination": {
                    "current_page": page,
                    "page_size": page_size,
                },
                "criteria": criteria,
                "sort": {
                    "property": "USERNAME",
                    "operation": "ASC",
                },
            }
            resp = self._request(
                "POST",
                "/v2/certificate/search"
                "?ignoreerrors=true&defaults=true",
                json=payload,
            )
            if resp.status_code != 200:
                log.debug(f"Certificate search returned {resp.status_code}")
                break

            data = resp.json()
            certs = data.get("certificates", [])
            if not certs:
                break

            all_certs.extend(certs)
            total = data.get("pagination_summary", {}).get("total_certs", 0)
            log.debug(f"  Certificate search page {page}: "
                      f"{len(certs)} certs (total reported: {total})")

            # EJBCA's total_certs is unreliable until the last page
            # (known bug). Use page fullness to decide whether to continue.
            if len(certs) < page_size:
                break  # partial page = last page
            page += 1

        log.info(f"Certificate search returned {len(all_certs)} certificates")
        return all_certs[:max_results]

    def build_profile_map(self, max_results: int = 10000) -> dict:
        """Build username → profile info mapping via certificate search.

        Works around the EE search endpoint's missing profile fields by
        querying the certificate search endpoint (v2), which returns
        endEntityProfile and endEntityProfileId per certificate.

        Returns a dict: {username: {
            "endEntityProfile": "...",
            "endEntityProfileId": ...,
            "certificateProfile": "...",
        }}
        """
        log.info("Building profile map via certificate search...")
        certs = self.search_certificates_v2(
            criteria=[
                {"property": "QUERY", "value": "%", "operation": "LIKE"},
            ],
            max_results=max_results,
        )

        profile_map = {}
        if certs:
            # Log sample cert fields for diagnostic purposes
            sample = certs[0]
            log.debug(f"Sample cert fields: {list(sample.keys())}")
            log.debug(f"Sample cert username: {sample.get('username', '(missing)')}")
            log.debug(f"Sample cert issuerDN: {sample.get('issuerDN', '(missing)')}")
            log.debug(f"Sample cert subjectDN: {sample.get('subjectDN', '(missing)')}")
            log.debug(f"Sample cert serialNumber: "
                      f"{sample.get('serialNumber', '(missing)')}")
        else:
            log.warning("Certificate search returned 0 certs — "
                        "-ci will have no cert data to display")
        for cert in certs:
            username = cert.get("username")
            if not username:
                continue
            # Keep the most recent cert per user (by notBefore)
            existing = profile_map.get(username)
            if existing and cert.get("notBefore", 0) < existing.get("notBefore", 0):
                continue
            profile_map[username] = {
                "endEntityProfile": cert.get("endEntityProfile", ""),
                "endEntityProfileId": cert.get("endEntityProfileId"),
                "certificateProfile": cert.get("certificateProfile", ""),
                "certificateProfileId": cert.get("certificateProfileId"),
                "issuerDN": cert.get("issuerDN", ""),
                "subjectDN": cert.get("subjectDN", ""),
                "serialNumber": cert.get("serialNumber", ""),
                "notBefore": cert.get("notBefore"),
                "expireDate": cert.get("expireDate"),
                "certStatus": cert.get("status"),
                "revocationDate": cert.get("revocationDate"),
                "revocationReason": cert.get("revocationReason"),
            }

        log.info(f"Profile map: {len(profile_map)} entities with profile data")
        return profile_map

    def search_certs_for_username(self, username: str,
                                   max_results: int = 10000) -> list[dict]:
        """Search for all certificates belonging to a specific username.

        Returns a list of certificate records sorted by notBefore (newest
        first).  Used by cert-report and count to show per-EE cert
        accumulation.  Returns up to max_results; if the list length
        equals max_results, the true count may be higher.
        """
        certs = self.search_certificates_v2(
            criteria=[
                {"property": "QUERY", "value": username,
                 "operation": "EQUAL"},
            ],
            max_results=max_results,
        )
        # Sort newest first
        certs.sort(key=lambda c: c.get("notBefore", 0), reverse=True)
        return certs

    def enrich_end_entities(self, entities: list[dict],
                            profile_map: dict) -> list[dict]:
        """Enrich EE search results with profile + cert data.

        The EE search response omits profile fields. This method merges in
        profile and certificate information obtained via build_profile_map().
        """
        enriched = 0
        cert_fields = ("endEntityProfile", "endEntityProfileId",
                       "certificateProfile", "certificateProfileId",
                       "issuerDN", "subjectDN",
                       "serialNumber", "notBefore", "expireDate",
                       "certStatus", "revocationDate", "revocationReason")
        for ee in entities:
            username = ee.get("username")
            if username and username in profile_map:
                pinfo = profile_map[username]
                for field in cert_fields:
                    if field in pinfo:
                        ee[field] = pinfo[field]
                enriched += 1

        log.info(f"Enriched {enriched}/{len(entities)} entities with "
                 f"profile + cert data (via certificate search)")
        if enriched == 0 and len(entities) > 0:
            # Detailed diagnostic for enrichment failures
            ee_names = {ee.get("username", "") for ee in entities if ee.get("username")}
            cert_names = set(profile_map.keys())
            log.warning("No entities matched cert search results by username.")
            log.warning(f"  EE usernames (sample): {sorted(list(ee_names))[:5]}")
            log.warning(f"  Cert usernames (sample): {sorted(list(cert_names))[:5]}")
            log.warning("Possible causes: username case mismatch, "
                        "cert search returned 0 certs, "
                        "or usernames differ between EE and cert records. "
                        "Try: -vv for debug, or --dump-json to inspect raw data.")
        elif enriched < len(entities):
            unenriched = len(entities) - enriched
            log.debug(f"  {unenriched} entities had no matching cert data")
        return entities

    def get_end_entity_profile(self, profile_name: str) -> Optional[dict]:
        """GET /v2/endentity/profile/{name} — Get profile definition."""
        if self._ee_backend is not None:
            return self._ee_backend.get_end_entity_profile(profile_name)
        resp = self._request("GET", f"/v2/endentity/profile/{profile_name}",
                             log_errors=False)
        if resp.status_code == 200:
            return resp.json()
        log.debug(f"Could not fetch profile '{profile_name}': {resp.status_code}")
        return None

    def get_authorized_profiles(self) -> Optional[dict]:
        """GET /v2/endentity/profiles/authorized/ — List authorized EE profiles.

        Returns a dict mapping profile name → profile ID (as string),
        or None if the endpoint is not available (requires EJBCA ≥ 7.10).

        Example response from EJBCA:
          {"end_entity_profiles": {"home_SG-ClientAuth-End-Entity": 597426056}}
        or possibly:
          {"end_entity_profiles": [{"name": ..., "id": ...}, ...]}
        """
        if self._ee_backend is not None:
            return self._ee_backend.get_authorized_profiles()
        resp = self._request("GET", "/v2/endentity/profiles/authorized/",
                             log_errors=False)
        if resp.status_code == 200:
            data = resp.json()
            log.debug(f"Authorized profiles response: {json.dumps(data, indent=2)}")
            # The response structure may vary; handle common formats
            profiles_raw = data.get("end_entity_profiles",
                           data.get("endEntityProfiles",
                           data.get("end_entitie_profiles",  # EJBCA typo
                           data)))
            # Could be a dict {name: id} or a list of objects
            if isinstance(profiles_raw, dict):
                # Direct name→id mapping
                return {str(k): str(v) for k, v in profiles_raw.items()}
            elif isinstance(profiles_raw, list):
                # List of objects — try to extract name and id
                result = {}
                for item in profiles_raw:
                    if isinstance(item, dict):
                        name = (item.get("name", "") or
                                item.get("profile_name", "") or
                                item.get("end_entity_profile_name", ""))
                        pid = (item.get("id", "") or
                               item.get("profile_id", ""))
                        if name and pid:
                            result[str(name)] = str(pid)
                return result if result else None
            return None
        log.debug(f"Authorized profiles endpoint returned {resp.status_code} "
                  f"(requires EJBCA ≥ 7.10)")
        return None

    def resolve_profile_id(self, profile_name: str) -> Optional[str]:
        """Resolve an End Entity Profile name to its database ID.

        Strategy:
          1. GET /v2/endentity/profiles/authorized/ → name→ID map (EJBCA ≥ 7.10)
          2. Fall back to GET /v2/endentity/profile/{name} and hope for an ID field

        Returns the numeric ID as a string, or None.
        """
        # Strategy 1: authorized profiles endpoint (preferred)
        profiles = self.get_authorized_profiles()
        if profiles:
            # Case-insensitive name match
            for name, pid in profiles.items():
                if name.lower() == profile_name.lower():
                    log.info(f"Resolved profile '{profile_name}' → ID {pid}")
                    return str(pid)
            avail = "\n".join(f"    {n}" for n in sorted(profiles.keys()))
            log.warning(f"Profile '{profile_name}' not found in authorized "
                        f"profiles.\n  Available:\n{avail}")
            return None

        # Strategy 2: individual profile GET (unlikely to have ID, but try)
        log.debug("Authorized profiles endpoint unavailable; trying "
                  "individual profile GET")
        profile = self.get_end_entity_profile(profile_name)
        if profile:
            for key in ("id", "profile_id", "profileId",
                        "end_entity_profile_id"):
                val = profile.get(key)
                if val is not None:
                    log.info(f"Resolved profile '{profile_name}' → ID {val}")
                    return str(val)
            log.debug(f"Profile GET returned fields {list(profile.keys())} "
                      f"— no ID field found")
        return None

    def list_authorized_profiles(self) -> Optional[dict]:
        """Convenience: return name→ID map, or None if unavailable."""
        return self.get_authorized_profiles()

    def resolve_profile_name(self, profile_id: str) -> Optional[str]:
        """Reverse-resolve a numeric profile ID → profile name.

        Uses the authorized profiles endpoint to find the name.
        Returns the name, or None if not found.
        """
        profiles = self.get_authorized_profiles()
        if profiles:
            for name, pid in profiles.items():
                if str(pid) == str(profile_id):
                    return name
        return None

    def list_cas(self) -> dict:
        """GET /v1/ca — Return a map of subjectDN → CA id (int).

        Used to look up CA IDs for display alongside CA names.
        Returns an empty dict if the endpoint is unavailable.
        """
        resp = self._request("GET", "/v1/ca", log_errors=False)
        if resp.status_code != 200:
            log.debug(f"GET /v1/ca returned {resp.status_code}: {resp.text[:200]}")
            return {}
        data = resp.json()
        result = {}
        for ca in data.get("certificate_authorities", []):
            dn = ca.get("subject_dn") or ca.get("subjectDn") or ""
            ca_id = ca.get("id")
            if dn and ca_id is not None:
                result[dn] = ca_id
        log.debug(f"list_cas: found {len(result)} CAs")
        return result


# ---------------------------------------------------------------------------
# Kubernetes cert-manager integration
# ---------------------------------------------------------------------------

def get_certmanager_certificates(kubectl_cmd: str = "kubectl") -> list[dict]:
    """
    Query Kubernetes for active cert-manager Certificate resources.
    Requires kubectl (or equivalent) to be configured.
    Returns a list of dicts with name, namespace, commonName, dnsNames.
    """
    try:
        # Support multi-word commands like '/snap/bin/microk8s kubectl'
        base_cmd = shlex.split(kubectl_cmd)
        full_cmd = base_cmd + ["get", "certificates", "--all-namespaces",
             "-o", "json"]
        log.debug(f"kubectl command: {' '.join(full_cmd)}")
        result = subprocess.run(
            full_cmd,
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            log.error(f"kubectl failed: {result.stderr.strip()}")
            return []
        data = json.loads(result.stdout)
        certs = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            status = item.get("status", {})
            certs.append({
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
                "commonName": spec.get("commonName", ""),
                "dnsNames": spec.get("dnsNames", []),
                "secretName": spec.get("secretName", ""),
                "issuerRef": spec.get("issuerRef", {}),
                "ready": any(
                    c.get("type") == "Ready" and c.get("status") == "True"
                    for c in status.get("conditions", [])
                ),
                "notAfter": status.get("notAfter", ""),
            })
        log.debug(f"kubectl returned {len(certs)} cert-manager Certificate resources")
        return certs
    except FileNotFoundError:
        log.error(f"kubectl not found: '{kubectl_cmd}'"
                  f"\n    Use -kubectl PATH or set ELT_KUBECTL"
                  f"\n    Example: -kubectl '/snap/bin/microk8s kubectl'")
        return []
    except subprocess.TimeoutExpired:
        log.error("kubectl timed out")
        return []
    except json.JSONDecodeError as e:
        log.error(f"Failed to parse kubectl output: {e}")
        return []


def build_k8s_identity_set(cm_certs: list[dict]) -> set[str]:
    """
    Build a set of identity strings from cert-manager Certificate resources.
    Uses commonName and dnsNames to match against EJBCA End Entity names.
    """
    identities = set()
    for cert in cm_certs:
        cn = cert.get("commonName", "")
        if cn:
            identities.add(cn.lower())
        for dns in cert.get("dnsNames", []):
            identities.add(dns.lower())
        # Also add the cert-manager resource name as a possible match
        name = cert.get("name", "")
        if name:
            identities.add(name.lower())
    return identities


# ---------------------------------------------------------------------------
# Certificate display helpers (for -cg / --cert-info)
# ---------------------------------------------------------------------------

def _format_serial(serial_hex: str) -> str:
    """Format a hex serial number with colons: AABB → aa:bb."""
    s = serial_hex.lower()
    return ":".join(s[i:i+2] for i in range(0, len(s), 2))


def _is_cert_revoked(cert: dict) -> bool:
    """Check if a certificate status indicates revoked/archived.

    Primary check: status field (string or numeric).
    Known EJBCA values: ACTIVE/20, REVOKED/40, ARCHIVED/50, EXPIRED/60.
    Status 60 (CERT_EXPIRED) requires a secondary revocationReason check
    to distinguish "expired and revoked" from "simply expired".

    Fallback: revocationReason field for any other unexpected status.
    EJBCA uses -1 (NOT_REVOKED) for active certs and 0-10 for revoked.
    """
    s = str(cert.get("status", "")).upper()
    reason = str(cert.get("revocationReason", "") or "").upper()
    # Numeric NOT_REVOKED (-1) or string NOT_REVOKED
    NOT_REVOKED = {"NOT_REVOKED", "", "-1"}

    if s in ("REVOKED", "ARCHIVED", "40", "50"):
        return True
    # Status 60 = CERT_EXPIRED: revoked-and-expired vs simply-expired
    if s == "60":
        revoked = reason not in NOT_REVOKED
        if revoked:
            log.debug(f"_is_cert_revoked: status=60 (expired+revoked),"
                      f" reason={reason!r}")
        return revoked
    # Fallback: unexpected status but non-trivial revocationReason
    if reason and reason not in NOT_REVOKED:
        log.debug(f"_is_cert_revoked: status={s!r} reason={reason!r}"
                  f" — treating as revoked (fallback)")
        return True
    return False


def _is_cert_past_expiry(cert: dict) -> bool:
    """True if cert's expireDate is before current wall-clock time. Used as
    the authoritative expiry check since EJBCA's status field may lag (the
    move from ACTIVE (20) to CERT_EXPIRED (60) happens only when a periodic
    CertificateUpdateService job runs, which can lag by minutes to hours).
    """
    expire_ms = cert.get("expireDate")
    if expire_ms is None:
        return False
    try:
        return int(expire_ms) < int(time.time() * 1000)
    except (ValueError, TypeError):
        return False


def _is_cert_expired(cert: dict) -> bool:
    """True if cert is expired-but-never-revoked. Either signal counts:
      * EJBCA status == 60 / EXPIRED / CERT_EXPIRED (DB caught up), OR
      * expireDate < now (wall-clock authority, status field stale).
    Revoked certs are NOT classified expired (caller cares about revocation).
    """
    if _is_cert_revoked(cert):
        return False
    s = str(cert.get("status", "")).upper()
    if s in ("60", "EXPIRED", "CERT_EXPIRED"):
        return True
    return _is_cert_past_expiry(cert)


def _is_cert_active(cert: dict) -> bool:
    """True if cert is genuinely usable right now: not revoked, not expired
    (by either EJBCA status or wall-clock), and status indicates ACTIVE
    or NOTIFIEDABOUTEXPIRATION (20 or 21).
    """
    if _is_cert_revoked(cert):
        return False
    if _is_cert_expired(cert):
        return False
    s = str(cert.get("status", "")).upper()
    return s in ("20", "21", "ACTIVE", "NOTIFIEDABOUTEXPIRATION")


def _summarize_cert_counts(certs: list) -> tuple:
    """Return (active, expired, revoked_expired, revoked_unexpired, other)
    counts. Buckets are mutually exclusive and partition the input.

    The revoked split distinguishes:
      * 'R' revoked+expired  — already past notAfter, prunable from CRL
      * 'r' revoked+unexpired — still requires active CRL/OCSP coverage
    'other' catches any status not in {ACTIVE, NOTIFIED-, REVOKED, ARCHIVED,
    EXPIRED} — typically zero in practice.
    """
    active = expired = revoked_expired = revoked_unexpired = 0
    for c in certs:
        if _is_cert_revoked(c):
            if _is_cert_past_expiry(c):
                revoked_expired += 1
            else:
                revoked_unexpired += 1
        elif _is_cert_expired(c):
            expired += 1
        elif _is_cert_active(c):
            active += 1
    other = (len(certs) - active - expired
             - revoked_expired - revoked_unexpired)
    return active, expired, revoked_expired, revoked_unexpired, other


def _format_cert_breakdown(active: int, expired: int,
                            revoked_expired: int, revoked_unexpired: int,
                            other: int = 0) -> str:
    """Format the cert-status count tuple as a self-explaining string.

    Each nonzero bucket appears as '{N}:{FLAG} {short-label}', so the
    same line tells readers what the single-letter flags in the cert
    table mean. Zero buckets are skipped. Example:
        '1:A active,  7:E expired,  20:R revoked+expired,  7:r revoked+unexpired'
    Empty input → 'none'.
    """
    parts = []
    if active:
        parts.append(f"{active}:A active")
    if expired:
        parts.append(f"{expired}:E expired")
    if revoked_expired:
        parts.append(f"{revoked_expired}:R revoked+expired")
    if revoked_unexpired:
        parts.append(f"{revoked_unexpired}:r revoked+unexpired")
    if other:
        parts.append(f"{other}:? other")
    return ",  ".join(parts) if parts else "none"


def _cert_flag(cert: dict) -> str:
    """Single-letter status flag for the cert table: A/E/R/r/?. Same
    vocabulary as _format_cert_breakdown so flag glyphs in the table
    line up with the counts in the summary line."""
    if _is_cert_revoked(cert):
        return "R" if _is_cert_past_expiry(cert) else "r"
    if _is_cert_expired(cert):
        return "E"
    if _is_cert_active(cert):
        return "A"
    return "?"


def _single_cert_label(cert: dict) -> str:
    """Return e.g. 'A active' / 'R revoked+expired' / 'r revoked+unexpired'
    for one cert. Same vocabulary as _format_cert_breakdown so 1-cert and
    N-cert displays use consistent flag-glossing labels.
    """
    if _is_cert_revoked(cert):
        if _is_cert_past_expiry(cert):
            return "R revoked+expired"
        return "r revoked+unexpired"
    if _is_cert_expired(cert):
        return "E expired"
    if _is_cert_active(cert):
        return "A active"
    return "? other"


def _print_cert_status_hints(revoked_unexpired: int) -> None:
    """Print operational follow-up hints below a Certificates: count line.

    First hint always prints — DBMS reaping is a non-obvious but useful
    EJBCA feature worth surfacing on every cert listing.
    Second hint prints only when 'r' (revoked+unexpired) > 0 — without
    that bucket present, the cert-manager/issuer comment is context-free.
    """
    print('  - Use the updated "DBMS Reaper" services to remove'
          ' inactive certificates as desired.')
    if revoked_unexpired:
        print("  - Repeated cert reqs from K8s cert-manager &"
              " EJBCA-Issuer <v2.2.0 can give 'r' status.")


def _format_cert_time(epoch_ms) -> str:
    """Format an epoch-millisecond timestamp as 'Mar 04 09:10:59 2026 GMT'."""
    if not epoch_ms or epoch_ms < 0:
        return ""
    dt = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def _split_dn(dn: str) -> list[str]:
    """Split a DN string into RDN components, respecting commas inside values.

    EJBCA returns DNs like 'CN=JohnB, ML-DSA-44,OU=bar,C=CH'.
    A comma is a field delimiter only when followed by a known attribute
    keyword and '='.  Commas inside values (like the CN above) are preserved.
    """
    # Split on comma followed by optional space and an attribute keyword + '='
    # Known attrs: CN, OU, O, C, L, ST, DC, SN, GN, serialNumber, emailAddress,
    # and OID dotted notation like 2.5.4.97
    parts = re.split(r',\s*(?=(?:[A-Za-z][A-Za-z0-9]*|[0-9]+(?:\.[0-9]+)+)\s*=)', dn)
    return [p.strip() for p in parts if p.strip()]


def _dn_unescape(val: str) -> str:
    r"""Remove DN backslash escapes for display: 'foo\, bar' → 'foo, bar'."""
    return val.replace("\\,", ",").replace("\\+", "+").replace("\\=", "=")


def _rdn_cn_value(rdn: str) -> str:
    """Extract CN value from a single RDN component, or '' if not a CN.

    Handles both 'CN=value' and 'CN = value' formats.
    Strips backslash escapes for display.
    """
    m = re.match(r'(?i)\s*CN\s*=\s*(.*)', rdn)
    return _dn_unescape(m.group(1).strip()) if m else ""


def _extract_cn(dn: str) -> str:
    """Extract the CN value from a DN string, handling commas in values."""
    for rdn in _split_dn(dn):
        val = _rdn_cn_value(rdn)
        if val:
            return val
    return dn  # fallback: return full DN


def _format_dn_display(dn: str, full_dn: bool = False) -> str:
    """Format a DN for display.

    Default mode: show just 'CN = <value>'
    Full mode (-ci2): show full DN with spaces around '='
    """
    if not dn:
        return ""
    if full_dn:
        parts = []
        for rdn in _split_dn(dn):
            if "=" in rdn:
                k, v = rdn.split("=", 1)
                parts.append(f"{k.strip()} = {_dn_unescape(v.strip())}")
            else:
                parts.append(_dn_unescape(rdn))
        return ", ".join(parts)
    else:
        cn = _extract_cn(dn)
        return f"CN = {cn}"


def _print_cert_section(ee: dict, full_dn: bool = False,
                        verbose_san: str = "") -> bool:
    """Print the certificate detail section for an enriched entity.

    Returns True if cert data was printed, False otherwise.
    full_dn: show full DN (all RDN components) instead of just CN.
    verbose_san: SAN string to display (passed from EE data).
    """
    issuer = ee.get("issuerDN", "")
    subject = ee.get("subjectDN", "")
    serial = ee.get("serialNumber", "")
    not_before = ee.get("notBefore")
    expire = ee.get("expireDate")
    cert_status = ee.get("certStatus")
    rev_date = ee.get("revocationDate")
    rev_reason = ee.get("revocationReason")

    if not (issuer or subject or serial):
        log.debug(f"No cert data for entity '{ee.get('username', '?')}' "
                  f"(cert search may not have matched this username)")
        return False

    print(f"\n  -- certificate --")
    if issuer:
        print(f"    Issuer:          {_format_dn_display(issuer, full_dn)}")
    if subject:
        print(f"    Subject:         {_format_dn_display(subject, full_dn)}")
    if serial:
        print(f"    Serial Number:   {_format_serial(serial)}")
    if not_before:
        print(f"    Not Before:      {_format_cert_time(not_before)}")
    if expire:
        print(f"    Not After:       {_format_cert_time(expire)}")
    if cert_status and str(cert_status) == "REVOKED":
        reason_str = rev_reason or "unknown"
        date_str = _format_cert_time(rev_date) if rev_date else "unknown"
        print(f"    Revoked:         {reason_str} ({date_str})")
    print(f"    SAN:             {verbose_san or '(none)'}")
    print()
    return True


# ---------------------------------------------------------------------------
# Profile filter helper
# ---------------------------------------------------------------------------

def _resolve_ee_profile(ee_profile_value: str, client: EjbcaClient
                        ) -> tuple[Optional[str], Optional[str]]:
    """Resolve -ee-profile value to (profile_name, profile_id).

    Auto-detects name vs numeric ID.
    Handles special values: 'orphans'/'(orphans)'.
    Returns (name, id) tuple.  Either may be None.
    """
    if not ee_profile_value:
        return None, None

    val = ee_profile_value.strip()

    # Special: orphans
    if val.lower().strip("()") == "orphans":
        log.info("Profile filter: (orphans) — entities with no profile")
        return "(orphans)", None

    # Auto-detect: all digits → ID, otherwise name
    if val.isdigit():
        log.info(f"Profile filter by ID: {val}")
        # Try to reverse-resolve name
        resolved = client.resolve_profile_name(val)
        if resolved:
            log.info(f"Resolved profile ID {val} → '{resolved}'")
            return resolved, val
        return None, val
    else:
        log.info(f"Resolving profile name '{val}' → ID")
        profile_id = client.resolve_profile_id(val)
        if profile_id:
            log.info(f"Profile validated: '{val}' (ID {profile_id})")
            return val, profile_id
        # Resolution failed
        log.error(
            f"Could not resolve profile '{val}' to an ID.\n"
            f"  Possible causes:\n"
            f"  - Profile name mismatch (case-sensitive)\n"
            f"  - Client cert not authorized for this profile\n"
            f"  - EJBCA version < 7.10 (no authorized profiles endpoint)\n"
            f"\n"
            f"  Try: elt list1  to see available profiles.\n"
            f"  Or:  use -ee-profile <ID> with a numeric ID."
        )
        sys.exit(1)


def _parse_issuer_yaml(filepath: str) -> Optional[str]:
    """Extract endEntityProfileName from a cert-manager Issuer YAML file.

    Uses simple line parsing to avoid requiring PyYAML.
    Handles both quoted and unquoted values.
    """
    try:
        with open(filepath, "r") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("endEntityProfileName:"):
                    value = stripped.split(":", 1)[1].strip()
                    # Remove surrounding quotes if present
                    if (value.startswith('"') and value.endswith('"')) or \
                       (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]
                    if value:
                        return value
    except FileNotFoundError:
        log.error(f"Issuer file not found: {filepath}")
        sys.exit(1)
    except IOError as e:
        log.error(f"Cannot read issuer file: {e}")
        sys.exit(1)
    return None


def _profile_matches(ee_profile: str, ee_profile_id, profile_name: str,
                     profile_id: str) -> bool:
    """Check if an EE matches the requested profile filter.

    Handles the virtual '(orphans)' profile for entities with no profile.
    Returns True if the entity should be INCLUDED, False if filtered out.
    """
    is_orphan = not ee_profile
    filter_orphans = (profile_name and
                      profile_name.lower().strip("()") == "orphans")

    if filter_orphans:
        return is_orphan

    # If filtering by name, orphans don't match any named profile
    if profile_name:
        if is_orphan:
            return False
        if ee_profile.lower() != profile_name.lower():
            return False

    if profile_id and ee_profile_id is not None:
        if str(ee_profile_id) != str(profile_id):
            return False

    return True


def _build_cert_profile_groups(entities: list[dict]) -> dict:
    """Build a map of EE profile → cert profiles with IDs.

    Used to determine whether to show cert profile in the section
    banner (single) or per-entry (multiple).
    Returns: {ee_profile_key: dict(cert_profile_name → id_or_None)}
    """
    groups = {}
    for ee in entities:
        key = ee.get("endEntityProfile", "") or "(orphans)"
        cp = ee.get("certificateProfile", "")
        cpid = ee.get("certificateProfileId")
        if key not in groups:
            groups[key] = {}
        if cp:
            groups[key][cp] = cpid
    return groups


def _print_profile_summary(profile_counts: dict):
    """Print aligned profile summary table.

    profile_counts: {(name, id_str): count, ...}
    """
    if not profile_counts:
        return
    # Compute column widths from data
    name_w = max(len(name) for name, _ in profile_counts) + 1
    id_w = max(len(pid) for _, pid in profile_counts)
    print(f"\n  By EE Profile:")
    for (p_name, p_id), count in sorted(profile_counts.items()):
        if p_id:
            print(f"    {p_name:<{name_w}s} ({p_id:>{id_w}s})  {count:>4d}")
        else:
            print(f"    {p_name:<{name_w}s} {'':<{id_w + 4}s}{count:>4d}")




# ---------------------------------------------------------------------------
# list command — detail levels -d1 through -d4
# ---------------------------------------------------------------------------

def _fetch_and_enrich(client, args,
                      profile_name: Optional[str] = None) -> list:
    """Fetch all EEs, enrich with profile data, sort, and return.

    profile_name: resolved EE profile name for server-side filtering.
    Pass the result of _resolve_ee_profile(), not args.ee_profile directly.
    """
    end_entities = client.search_all_end_entities(
        max_results=args.max_end_entities,
        status_filter=args.status_filter,
        profile_name=profile_name,
    )
    if not end_entities:
        return []
    profile_map = client.build_profile_map(max_results=args.max_certs)
    client.enrich_end_entities(end_entities, profile_map)
    end_entities.sort(key=lambda e: (
        e.get("endEntityProfile", "").lower(),
        e.get("username", e.get("name", "")).lower(),
    ))
    return end_entities


def _apply_filters(end_entities: list, profile_name: str,
                   profile_id: str, args) -> tuple:
    """Filter EEs by profile, active/revoked.  Returns (filtered, skipped)."""
    filtered = []
    skipped = 0
    for ee in end_entities:
        ep = ee.get("endEntityProfile", "")
        epid = ee.get("endEntityProfileId")
        if profile_name or profile_id:
            if not _profile_matches(ep, epid, profile_name, profile_id):
                skipped += 1
                continue
        if getattr(args, "active_only", False):
            if ee.get("status", "").upper() in ("REVOKED",):
                skipped += 1
                continue
        if getattr(args, "revoked_only", False):
            if ee.get("status", "").upper() not in ("REVOKED",):
                skipped += 1
                continue
        filtered.append(ee)
    return filtered, skipped


def _list_ghosts(args, client: EjbcaClient):
    """Display ghost EE usernames: cert records that outlived their deleted EE."""
    print(f"\n{'=' * 78}")
    print(f"Ghost EE Detection:  -ghosts")
    print(f"Generated:     {datetime.now(timezone.utc).isoformat()}")
    print(f"{'=' * 78}")
    sys.stdout.flush()
    print("  ... querying EJBCA REST API ...")

    ghost_map = find_ghost_usernames(
        client,
        max_ee=args.max_end_entities,
        max_certs=args.max_certs,
    )

    if not ghost_map:
        print("\n  No ghost EE usernames detected.")
        print(f"\n{'-' * 78}")
        print()
        return

    print(f"\n  Ghost EE usernames detected: {len(ghost_map)}")
    print(f"  (EE record deleted; certificate records persist until expiry)")

    for uname, certs in sorted(ghost_map.items()):
        active, expired, revoked_exp, revoked_unexp, _other = _summarize_cert_counts(certs)
        revoked = revoked_exp + revoked_unexp
        ee_profile = certs[0].get("endEntityProfile", "") if certs else ""
        cert_profile = certs[0].get("certificateProfile", "") if certs else ""

        print(f"\n  {'=' * 74}")
        print(f"  EE Username:   {uname}")
        print(f"  EE Status:     *** GHOST — EE deleted; "
              f"certificate records persist until expiry ***")
        if ee_profile:
            print(f"  EE Profile:    {ee_profile}")
        if cert_profile:
            print(f"  Cert Profile:  {cert_profile}")
        if args.detail != 4:
            print()
            print(f"  Certificates:  {len(certs)}:  "
                  f"{_format_cert_breakdown(active, expired, revoked_exp, revoked_unexp)}")
            _print_cert_status_hints(revoked_unexp)

        # Show cert table if detail level is 4
        if args.detail == 4:
            _print_ee_cert_table(client, uname, args.max_certs,
                                 ee_data=None,
                                 is_ghost=True,
                                 show_header=False,
                                 show_profile=False,
                                 show_full=getattr(args, "show_full", False),
                             cert_detail=args.cert_detail,
                             active_only=getattr(args, "active_only", False),
                             revoked_only=getattr(args, "revoked_only", False))

    print(f"{'-' * 78}" if args.detail == 4 else f"\n{'-' * 78}")
    print()


def cmd_list(args, client):
    """Unified list command with detail levels 1-4."""

    detail = args.detail

    # Warn about ignored flags
    if detail < 4 and args.cert_detail > 0:
        ci_flag = f"-ci{args.cert_detail}"
        log.warning(f"{ci_flag} ignored (only applies to list -d4)")

    # Cert filters imply -F and warn if not d4/count
    has_cert_filter = args.cert_cn or args.cert_serial
    if has_cert_filter:
        args.show_full = True
        if detail < 4:
            log.warning("- cert-cn/-cert-serial ignored "
                        "(only applies to list -d4 and count)")

    if args.k8s_compare and detail not in (3, 4):
        log.warning("-k8s-compare ignored (only applies to list -d3, -d4, count, and cleanup)")
    if getattr(args, "ghosts", False) and detail not in (3, 4):
        log.warning("-ghosts ignored at -d1/-d2 (use -d3, -d4, or count)")
    if args.k8s_status and detail not in (3, 4):
        log.warning("-k8s-status ignored (only applies to list -d3, -d4, and count)")
    if getattr(args, "sort_field", None) is not None:
        log.warning("-sort ignored (only applies to count)")

    # Resolve -ee-profile (auto-detect name vs ID)
    profile_name, profile_id = _resolve_ee_profile(
        args.ee_profile, client)

    # Read profile from issuer YAML if given
    if args.file and not args.ee_profile:
        yaml_profile = _parse_issuer_yaml(args.file)
        if yaml_profile:
            log.info(f"Using profile from issuer YAML: {yaml_profile}")
            profile_name = yaml_profile
            pid = client.resolve_profile_id(yaml_profile)
            if pid:
                profile_id = pid

    if getattr(args, "ghosts", False) and detail in (3, 4):
        _list_ghosts(args, client)
        return

    if detail == 1:
        _list_d1(args, client)
    elif detail == 2:
        _list_d2(args, client, profile_name, profile_id)
    elif detail == 3:
        _list_d3(args, client, profile_name, profile_id)
    elif detail == 4:
        _list_d4(args, client, profile_name, profile_id)


def _print_list_banner(args, detail: int, profile_name: str = None):
    """Print a consistent banner header for all list detail levels."""
    titles = {
        1: "End Entity Profiles:  list -d1",
        2: "End Entity Profiles with Certificate Profiles and CAs:  list -d2",
        3: "End Entity Listing with Certificate Counts:  list -d3",
        4: "EJBCA Certificates:  list -d4",
    }
    print(f"\n{'=' * 78}")
    print(titles.get(detail, f"list -d{detail}"))
    if profile_name:
        print(f"EE Profile:    {profile_name}")
    elif detail >= 3 and not getattr(args, 'ee_username', None):
        print(f"EE Profile:    (all)")
    if getattr(args, 'ee_username', None):
        print(f"EE Username:   {args.ee_username}")
    if getattr(args, 'cert_serial', None):
        print(f"Cert Serial:   {args.cert_serial}")
    if getattr(args, 'cert_cn', None):
        print(f"Cert CN:       {args.cert_cn}")
    if getattr(args, 'k8s_status', None):
        print(f"K8s Status:    {args.k8s_status}")
    elif getattr(args, 'k8s_compare', False):
        print(f"K8s Compare:   enabled")
    print(f"Generated:     {datetime.now(timezone.utc).isoformat()}")
    print(f"Host:          {args.ejbca_host}:{args.ejbca_port}")
    print(f"{'=' * 78}")
    sys.stdout.flush()


def _list_d1(args, client):
    """Level 1: EE Profile names + IDs."""

    log.info("Querying authorized End Entity Profiles")
    profiles = client.list_authorized_profiles()

    if profiles is None:
        print("\nCould not retrieve authorized profiles.")
        print("This endpoint requires EJBCA >= 7.10.")
        print("Check: REST End Entity Management v2 is enabled?")
        print("Check: Is your $ELT_CERT added as a role member associated with RA access rules?")
        print("Check: Is the CA of your $ELT_CERT added to the TRUSTED CA list?")
        return

    if not profiles:
        print("\nNo authorized profiles found for this client certificate.")
        print("Check: Is your $ELT_CERT added as a role member associated with RA access rules?")
        print("Check: Is the CA of your $ELT_CERT added to the TRUSTED CA list?")
        return

    _print_list_banner(args, 1)
    print(f"\n  {'EE Profile Name':<55s}  {'ID':>12s}")
    print(f"  {'-' * 55}  {'-' * 12}")
    for name, pid in sorted(profiles.items()):
        print(f"  {name:<55s}  {pid:>12s}")
    print(f"\n{'-' * 78}")
    print(f"Total: {len(profiles)} profiles")
    print(f"{'-' * 78}")


def _list_d2(args, client, profile_name, profile_id):
    """Level 2: EE Profiles + associated Cert Profiles + CAs with IDs."""

    _print_list_banner(args, 2, profile_name)
    print("  ... querying EJBCA REST API ...")

    end_entities = _fetch_and_enrich(client, args, profile_name=profile_name)
    if not end_entities:
        print("\nNo End Entities found.")
        return

    entities, skipped = _apply_filters(
        end_entities, profile_name, profile_id, args)

    # Fetch CA id map: subjectDN → int id
    ca_dn_to_id = client.list_cas()

    profile_map = {}
    profile_ids = {}
    for ee in entities:
        ep = ee.get("endEntityProfile", "") or "(orphans)"
        cp = ee.get("certificateProfile", "")
        cpid = ee.get("certificateProfileId")
        issuer_dn = ee.get("issuerDN", "")
        ca_name = _extract_cn(issuer_dn) if issuer_dn else ""
        ca_id = ca_dn_to_id.get(issuer_dn) if issuer_dn else None
        epid = ee.get("endEntityProfileId")
        if ep not in profile_map:
            profile_map[ep] = {"cert_profiles": {}, "cas": {}}
            profile_ids[ep] = epid
        # cert_profiles: name → id (last seen wins; ids should be stable)
        if cp:
            profile_map[ep]["cert_profiles"][cp] = cpid
        # cas: name → id
        if ca_name:
            profile_map[ep]["cas"][ca_name] = ca_id

    def _id_str(id_val):
        return f"({id_val})" if id_val is not None else ""

    # Compute global alignment: max name width across ALL ep/cp/ca names
    all_names = []
    for ep_name, data in profile_map.items():
        all_names.append(ep_name)
        all_names.extend(data["cert_profiles"].keys() or ["(unknown)"])
        all_names.extend(data["cas"].keys() or ["(unknown)"])
    pad = max(len(n) for n in all_names) + 2  # 2 spaces between name and (id)

    print()
    first = True
    for ep_name in sorted(profile_map.keys(), key=str.lower):
        if not first:
            print()
        first = False
        epid = profile_ids.get(ep_name)
        cp_map = profile_map[ep_name]["cert_profiles"]
        ca_map = profile_map[ep_name]["cas"]

        cp_names = sorted(cp_map) if cp_map else ["(unknown)"]
        ca_names = sorted(ca_map) if ca_map else ["(unknown)"]

        ep_id_s = _id_str(epid)
        print(f"  EE Profile:    {ep_name:<{pad}s}{ep_id_s}")
        for cp in cp_names:
            cp_id_s = _id_str(cp_map.get(cp)) if cp != "(unknown)" else ""
            print(f"  Cert Profile:  {cp:<{pad}s}{cp_id_s}")
        for ca in ca_names:
            ca_id_s = _id_str(ca_map.get(ca)) if ca != "(unknown)" else ""
            print(f"  CA:            {ca:<{pad}s}{ca_id_s}")

    print(f"\n{'-' * 78}")
    print(f"Total: {len(profile_map)} EE Profiles")
    if skipped:
        print(f"Skipped (other EE profiles): {skipped}")
    print(f"{'-' * 78}")


def _list_d3(args, client, profile_name, profile_id):
    """Level 3: EE Profiles + EE usernames with cert counts."""

    if args.ee_username:
        _list_d3_single(args, client)
        return

    _print_list_banner(args, 3, profile_name)
    print("  ... querying EJBCA REST API ...")

    end_entities = _fetch_and_enrich(client, args, profile_name=profile_name)
    if not end_entities:
        print("\nNo End Entities found.")
        return

    entities, skipped = _apply_filters(
        end_entities, profile_name, profile_id, args)

    cert_profile_groups = _build_cert_profile_groups(entities)

    _banner_names = list(cert_profile_groups)
    for _cp_map in cert_profile_groups.values():
        _banner_names.extend(_cp_map.keys())
    banner_pad = max((len(n) for n in _banner_names), default=0) + 2

    k8s_identities = None
    if args.k8s_compare:
        log.info("Cross-referencing with Kubernetes cert-manager...")
        cm_certs = get_certmanager_certificates(kubectl_cmd=args.kubectl)
        k8s_identities = build_k8s_identity_set(cm_certs)

    display_limit = 3
    displayed = 0
    k8s_filtered = 0
    truncated = False
    total_certs = 0
    prev_profile = None

    for ee in entities:
        ee_name = ee.get("username", ee.get("name", "unknown"))
        ee_profile = ee.get("endEntityProfile", "")
        ee_profile_id = ee.get("endEntityProfileId")
        ee_status = ee.get("status", "UNKNOWN")
        ee_token = ee.get("token", "")

        cur_profile = ee_profile or "(orphans)"

        # Compute K8s status early so we can filter before API calls
        k8s_status = ""
        if k8s_identities is not None:
            is_orphaned = ee_name.lower() not in k8s_identities
            if is_orphaned and ee.get("dn"):
                for rdn in _split_dn(ee.get("dn", "")):
                    rdn = rdn.strip()
                    cn_val = _rdn_cn_value(rdn)
                    if cn_val and cn_val.lower() in k8s_identities:
                            is_orphaned = False
                            break
            k8s_status = "orphaned (not in this K8s context)" if is_orphaned else "active in K8s"

            # Filter by -k8s-status if specified
            if args.k8s_status:
                if args.k8s_status == "orphaned" and not is_orphaned:
                    k8s_filtered += 1
                    continue
                if args.k8s_status == "active" and is_orphaned:
                    k8s_filtered += 1
                    continue

        displayed += 1

        if not args.show_full and displayed > display_limit:
            if not truncated:
                print(f"\n  ... {display_limit} of {len(entities)} EEs shown;"
                      f" use -F / --full to list all ...")
                sys.stdout.flush()
                truncated = True
            break

        certs = client.search_certs_for_username(
            ee_name, max_results=args.max_certs)
        n_certs = len(certs)
        active, expired, revoked_exp, revoked_unexp, _other = _summarize_cert_counts(certs)
        revoked = revoked_exp + revoked_unexp
        total_certs += n_certs


        if cur_profile != prev_profile:
            if prev_profile is not None:
                print()
            _ep_label = ee_profile or "(orphans)"
            _ep_id_s = f" ({ee_profile_id})" if ee_profile_id else ""
            print(f"\n  ------------")
            print(f"  EE Profile:    {_ep_label:<{banner_pad}s}{_ep_id_s}")
            cp_map = cert_profile_groups.get(cur_profile, {})
            if len(cp_map) == 1:
                cp_name, cp_id = next(iter(cp_map.items()))
                cp_id_s = f" ({cp_id})" if cp_id is not None else ""
                print(f"  Cert Profile:  {cp_name:<{banner_pad}s}{cp_id_s}")
            elif len(cp_map) > 1:
                print(f"  Cert Profile:  (multiple)")
            else:
                print(f"  Cert Profile:  (unknown)")
            print(f"  ------------")
            sys.stdout.flush()
        prev_profile = cur_profile

        print(f"\n  EE Username:   {ee_name}")
        if k8s_status:
            print(f"  K8s Status:    {k8s_status}")
        print(f"  EE Status:     {ee_status}")
        if ee_token:
            print(f"  EE Token:      {ee_token}")
        print()
        if n_certs == 0:
            print(f"  Certificates:  (none)")
        else:
            print(f"  Certificates:  {n_certs}:  "
                  f"{_format_cert_breakdown(active, expired, revoked_exp, revoked_unexp)}")
            _print_cert_status_hints(revoked_unexp)
        sys.stdout.flush()

    shown = min(displayed, display_limit) if truncated else displayed
    print(f"\n{'-' * 78}")
    if truncated:
        print(f"End Entities:    {shown} of {len(entities)} shown (truncated)")
        print(f"Certs counted:   {total_certs}")
    elif args.k8s_status:
        print(f"End Entities:    {displayed} of {len(entities)} "
              f"({args.k8s_status})")
        print(f"Total certs:     {total_certs}")
    else:
        print(f"End Entities:    {displayed}")
        print(f"Total certs:     {total_certs}")
    if skipped:
        print(f"Skipped (other EE profiles): {skipped}")
    if k8s_filtered:
        print(f"Filtered (-k8s-status):     {k8s_filtered}")
    print(f"{'-' * 78}")
    print()


def _list_d3_single(args, client):
    """Level 3 for a single -ee-username."""
    username = args.ee_username
    log.info(f"Listing cert summary for EE: {username}")

    _print_list_banner(args, 3)
    print("  ... querying EJBCA REST API ...")

    certs = client.search_certs_for_username(
        username, max_results=args.max_certs)

    if not certs:
        print("\n  (no certificates found)")
        print(f"\n{'-' * 78}")
        return

    active, expired, revoked_exp, revoked_unexp, _other = _summarize_cert_counts(certs)
    revoked = revoked_exp + revoked_unexp

    sample = certs[0]
    ee_profile = sample.get("endEntityProfile", "")
    cert_profile = sample.get("certificateProfile", "")

    print(f"  EE Profile:    {ee_profile or '(orphans)'}")
    if cert_profile:
        print(f"  Cert Profile:  {cert_profile}")
    print()
    print(f"  Certificates:  {len(certs)}:  "
          f"{_format_cert_breakdown(active, expired, revoked_exp, revoked_unexp)}")
    _print_cert_status_hints(revoked_unexp)

    print(f"\n{'-' * 78}")
    print()


def _list_d4(args, client, profile_name, profile_id):
    """Level 4: Full certificate tables per EE."""

    if args.ee_username:
        username = args.ee_username
        log.info(f"Listing all certificates for EE: {username}")
        _print_list_banner(args, 4)
        print("  ... querying EJBCA REST API ...")

        # Fetch EE record for status/token/key display
        ee_entities = client.search_all_end_entities(
            max_results=args.max_end_entities,
            status_filter=args.status_filter,
        )
        ee_data = None
        for ee in ee_entities:
            if ee.get("username", "") == username:
                ee_data = ee
                break
        is_ghost = False

        # Compute K8s status for single EE if requested
        k8s_status_single = ""
        if args.k8s_compare:
            cm_certs = get_certmanager_certificates(kubectl_cmd=args.kubectl)
            k8s_ids = build_k8s_identity_set(cm_certs)
            is_orphaned = username.lower() not in k8s_ids
            if is_orphaned and ee_data and ee_data.get("dn"):
                for rdn in _split_dn(ee_data.get("dn", "")):
                    cn_val = _rdn_cn_value(rdn)
                    if cn_val and cn_val.lower() in k8s_ids:
                        is_orphaned = False
                        break
            k8s_status_single = ("orphaned (not in this K8s context)"
                                 if is_orphaned else "active in K8s")

        _print_ee_cert_table(client, username, args.max_certs,
                             ee_data=ee_data,
                             is_ghost=is_ghost,
                             cert_cn=getattr(args, "cert_cn", None),
                             cert_serial=getattr(args, "cert_serial", None),
                             k8s_status=k8s_status_single,
                             show_full=getattr(args, "show_full", False),
                             cert_detail=args.cert_detail,
                             active_only=getattr(args, "active_only", False),
                             revoked_only=getattr(args, "revoked_only", False))
        print(f"{'-' * 78}")
        print()
        return

    _print_list_banner(args, 4, profile_name)
    print("  ... querying EJBCA REST API ...")

    end_entities = _fetch_and_enrich(client, args, profile_name=profile_name)
    if not end_entities:
        print("\nNo End Entities found.")
        return

    entities, skipped = _apply_filters(
        end_entities, profile_name, profile_id, args)

    cert_profile_groups = _build_cert_profile_groups(entities)

    _banner_names = list(cert_profile_groups)
    for _cp_map in cert_profile_groups.values():
        _banner_names.extend(_cp_map.keys())
    banner_pad = max((len(n) for n in _banner_names), default=0) + 2

    k8s_identities = None
    if args.k8s_compare:
        log.info("Cross-referencing with Kubernetes cert-manager...")
        cm_certs = get_certmanager_certificates(kubectl_cmd=args.kubectl)
        k8s_identities = build_k8s_identity_set(cm_certs)

    display_limit = 3
    displayed = 0
    matched = 0
    k8s_filtered = 0
    truncated = False
    total_certs = 0
    prev_profile = None
    has_cert_filter = getattr(args, "cert_cn", None) or getattr(args, "cert_serial", None)

    for ee in entities:
        ee_name = ee.get("username", ee.get("name", "unknown"))
        ee_profile = ee.get("endEntityProfile", "")
        ee_profile_id = ee.get("endEntityProfileId")
        ee_cert_profile = ee.get("certificateProfile", "")

        cur_profile = ee_profile or "(orphans)"

        # Compute K8s status early so we can filter before API calls
        k8s_status = ""
        if k8s_identities is not None:
            is_orphaned = ee_name.lower() not in k8s_identities
            if is_orphaned and ee.get("dn"):
                for rdn in _split_dn(ee.get("dn", "")):
                    rdn = rdn.strip()
                    cn_val = _rdn_cn_value(rdn)
                    if cn_val and cn_val.lower() in k8s_identities:
                            is_orphaned = False
                            break
            k8s_status = "orphaned (not in this K8s context)" if is_orphaned else "active in K8s"

            if args.k8s_status:
                if args.k8s_status == "orphaned" and not is_orphaned:
                    k8s_filtered += 1
                    continue
                if args.k8s_status == "active" and is_orphaned:
                    k8s_filtered += 1
                    continue

        displayed += 1

        if not args.show_full and displayed > display_limit:
            if not truncated:
                print(f"\n  ... {display_limit} of {len(entities)} EEs shown;"
                      f" use -F / --full to list all ..."
                      f"\n  (CAUTION: -F may produce very large output"
                      f" in environments with many certificates)")
                sys.stdout.flush()
                truncated = True
            break

        cp_map = cert_profile_groups.get(cur_profile, {})
        cp_override = ee_cert_profile if len(cp_map) > 1 else ""

        # When filtering by cert CN/serial, peek first to skip empty EEs
        if has_cert_filter:
            peek_certs = client.search_certs_for_username(
                ee_name, max_results=args.max_certs)
            peek_matched = _filter_certs(
                peek_certs,
                cert_cn=getattr(args, "cert_cn", None),
                cert_serial=getattr(args, "cert_serial", None))
            if not peek_matched:
                continue

        # Print profile banner when group changes
        if cur_profile != prev_profile:
            if prev_profile is not None:
                print()
            _ep_label = ee_profile or "(orphans)"
            _ep_id_s = f" ({ee_profile_id})" if ee_profile_id else ""
            print(f"\n  ------------")
            print(f"  EE Profile:    {_ep_label:<{banner_pad}s}{_ep_id_s}")
            if len(cp_map) == 1:
                cp_name, cp_id = next(iter(cp_map.items()))
                cp_id_s = f" ({cp_id})" if cp_id is not None else ""
                print(f"  Cert Profile:  {cp_name:<{banner_pad}s}{cp_id_s}")
            elif len(cp_map) > 1:
                print(f"  Cert Profile:  (multiple)")
            else:
                print(f"  Cert Profile:  (unknown)")
            print(f"  ------------")
            sys.stdout.flush()
        prev_profile = cur_profile

        n = _print_ee_cert_table(client, ee_name, args.max_certs,
                                 show_profile=False,
                                 cert_profile_override=cp_override,
                                 ee_data=ee,
                                 cert_cn=getattr(args, "cert_cn", None),
                                 cert_serial=getattr(args, "cert_serial", None),
                                 k8s_status=k8s_status,
                                 show_full=getattr(args, "show_full", False),
                             cert_detail=args.cert_detail,
                             active_only=getattr(args, "active_only", False),
                             revoked_only=getattr(args, "revoked_only", False))
        total_certs += n
        if n > 0:
            matched += 1

    # Fallback: cert-filter found nothing via EE loop — try direct cert API
    if has_cert_filter and matched == 0 and not args.ee_username:
        _serial = getattr(args, "cert_serial", None)
        _cn = getattr(args, "cert_cn", None)
        direct_certs = []
        if _serial:
            direct_certs = client.search_certs_by_serial(_serial)
        elif _cn:
            direct_certs = client.search_certificates_v2(
                criteria=[{"property": "QUERY", "value": _cn,
                            "operation": "LIKE"}],
                max_results=args.max_certs)
            direct_certs = _filter_certs(direct_certs, cert_cn=_cn)
        if direct_certs:
            by_user: dict = {}
            for _dc in direct_certs:
                _u = _dc.get("username", "(unknown)")
                by_user.setdefault(_u, []).append(_dc)
            print(f"  Note: EE record(s) deleted — showing ghost certificate records:")
            for _u in by_user:
                # EE confirmed absent (not in EE loop results above)
                _print_ee_cert_table(client, _u, args.max_certs,
                                     ee_data=None,
                                     is_ghost=True,
                                     cert_cn=_cn,
                                     cert_serial=_serial,
                                     show_full=getattr(args, "show_full", False),
                             cert_detail=args.cert_detail,
                             active_only=getattr(args, "active_only", False),
                             revoked_only=getattr(args, "revoked_only", False))
            total_certs = sum(len(v) for v in by_user.values())
            matched = len(by_user)

    print(f"{'-' * 78}")
    if truncated:
        shown = min(displayed, display_limit)
        print(f"End Entities:    {shown} of {len(entities)} shown (truncated)")
        print(f"Certs counted:   {total_certs}")
    elif has_cert_filter:
        print(f"End Entities:    {matched} of {len(entities)} matched")
        print(f"Certs matched:   {total_certs}")
    elif args.k8s_status:
        print(f"End Entities:    {displayed} of {len(entities)} "
              f"({args.k8s_status})")
        print(f"Total certs:     {total_certs}")
    else:
        print(f"End Entities:    {displayed}")
        print(f"Total certs:     {total_certs}")
    if skipped:
        print(f"Skipped (other EE profiles): {skipped}")
    if k8s_filtered:
        print(f"Filtered (-k8s-status):     {k8s_filtered}")
    print(f"{'-' * 78}")
    print()

# ---------------------------------------------------------------------------
# Ping mode
# ---------------------------------------------------------------------------

def _is_tls_verify_error(exc: BaseException) -> bool:
    """True if exc's str chain contains a TLS certificate-verify failure."""
    msg = str(exc)
    return ("CERTIFICATE_VERIFY_FAILED" in msg
            or "certificate verify failed" in msg.lower()
            or "SSLCertVerificationError" in msg)


def _fetch_server_cert_pem(host: str, port: int,
                            timeout: float = 5.0) -> Optional[str]:
    """Open a raw TLS socket (no verify) and return the server cert as PEM.

    Returns None if the TLS handshake itself fails (e.g. nothing listening,
    plain-HTTP port, network unreachable). Used by ping's TLS-failure
    diagnostic — we already know the verified handshake failed, so we
    retry unverified just to capture the cert the server presented.
    """
    import ssl, socket
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return None
                return ssl.DER_cert_to_PEM_cert(der)
    except Exception as e:
        log.debug(f"_fetch_server_cert_pem({host}:{port}) failed: {e}")
        return None


def _parse_cert_subject_issuer(pem: str) -> Optional[dict]:
    """Extract subject and issuer DN strings from a PEM cert via openssl.

    Returns {"subject": "...", "issuer": "..."} on success, None if openssl
    isn't on PATH or returned non-zero. Stdlib-only fallback: no cryptography
    library dependency.
    """
    try:
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer"],
            input=pem, capture_output=True, text=True, timeout=5,
        )
    except FileNotFoundError:
        log.debug("openssl not on PATH; cannot parse presented cert")
        return None
    except Exception as e:
        log.debug(f"openssl invocation failed: {e}")
        return None
    if result.returncode != 0:
        log.debug(f"openssl x509 returncode={result.returncode}: "
                  f"{result.stderr.strip()}")
        return None
    out = {}
    for line in result.stdout.splitlines():
        if line.startswith("subject="):
            out["subject"] = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            out["issuer"] = line[len("issuer="):].strip()
    return out or None


# Per-process cache: (host, port) → (presented_cert_dict | None, raw_pem | None)
# Keyed to avoid hitting the same TLS endpoint 4 times during one ping run.
_TLS_DIAG_CACHE: dict = {}


def _extract_cn(dn: str) -> Optional[str]:
    """Extract the Common Name from a DN string, robust to format variations.

    Handles both EJBCA-style (`CN=ELT-Admin,O=...`) and openssl-style
    (`subject=CN = ELT-Admin, O = ...`) without falling over. Used by
    fix 11's self-deletion guard, where the LHS of the comparison comes
    from openssl and the RHS comes from EJBCA's EE record.
    """
    if not dn:
        return None
    if dn.startswith("subject="):
        dn = dn[len("subject="):]
    m = re.search(r'CN\s*=\s*([^,/]+)', dn, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def _get_cert_cn(cert_path: str) -> Optional[str]:
    """Return the Subject CN of the cert file at cert_path, or None.

    Uses `openssl x509` for parsing (same approach as fix 7 — no
    cryptography Python dependency). Returns None silently if openssl
    isn't on PATH or the cert can't be parsed; the caller treats that
    as "no self-guard available" and proceeds without the guard rather
    than failing the whole operation.
    """
    if not cert_path:
        return None
    try:
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-in", cert_path],
            capture_output=True, text=True, timeout=5,
        )
    except FileNotFoundError:
        log.debug("openssl not on PATH; self-deletion guard disabled")
        return None
    except Exception as e:
        log.debug(f"_get_cert_cn({cert_path}) failed: {e}")
        return None
    if result.returncode != 0:
        return None
    return _extract_cn(result.stdout.strip())


def _diagnose_tls_verify(host: str, port: int) -> dict:
    """Return diagnostic info for a TLS verify failure at host:port.

    Result shape:
      {"available": True, "subject": "...", "issuer": "..."}
      {"available": True, "subject": None, "issuer": None, "pem": "..."}  # openssl missing
      {"available": False}                                                # handshake failed
    """
    key = (host, port)
    if key in _TLS_DIAG_CACHE:
        return _TLS_DIAG_CACHE[key]
    pem = _fetch_server_cert_pem(host, port)
    if pem is None:
        result = {"available": False}
    else:
        parsed = _parse_cert_subject_issuer(pem)
        if parsed is None:
            result = {"available": True, "subject": None,
                      "issuer": None, "pem": pem}
        else:
            result = {"available": True,
                      "subject": parsed.get("subject"),
                      "issuer": parsed.get("issuer")}
    _TLS_DIAG_CACHE[key] = result
    return result


def _format_tls_diag_line(diag: dict, indent: str = "      ") -> list[str]:
    """Format _diagnose_tls_verify() output as a list of indented lines."""
    if not diag.get("available"):
        return [f"{indent}(could not re-fetch presented cert — handshake "
                f"itself failed)"]
    if diag.get("subject"):
        return [f"{indent}presented cert subject: {diag['subject']}",
                f"{indent}presented cert issuer:  {diag['issuer']}"]
    # Cert fetched but couldn't be parsed (no openssl on PATH).
    return [f"{indent}(presented cert fetched but openssl not on PATH — "
            f"cannot parse subject/issuer)"]


def cmd_ping(args, client: EjbcaClient):
    """Probe REST and SOAP surfaces to verify connectivity and detect edition.

    v5.0.0 fixes 5/6/7: per-endpoint status lines; CE-aware verdict that
    treats REST 404 + SOAP OK as success; structured TLS-verify diagnostic
    that re-fetches the presented cert and reports subject/issuer instead
    of dumping the raw urllib3 stack.
    """
    # Reset per-run TLS diagnostic cache (otherwise repeated runs in the
    # same Python process — e.g. tests — see stale entries).
    _TLS_DIAG_CACHE.clear()
    if getattr(args, "cert_detail", 0) > 0:
        log.warning(f"-ci{args.cert_detail} ignored (not applicable to ping)")
    if getattr(args, "k8s_compare", False):
        log.warning("-k8s-compare ignored (not applicable to ping)")
    if getattr(args, "k8s_status", None):
        log.warning("-k8s-status ignored (not applicable to ping)")
    if getattr(args, "sort_field", None) is not None:
        log.warning("-sort ignored (only applies to count)")
    if getattr(args, "cert_cn", None):
        log.warning("-cert-cn ignored (not applicable to ping)")
    if getattr(args, "cert_serial", None):
        log.warning("-cert-serial ignored (not applicable to ping)")

    print(f"\n  EJBCA connectivity ping")
    print(f"  Host:        {args.ejbca_host}:{args.ejbca_port}")
    print(f"  Client cert: {args.client_cert}")
    print(f"  Client key:  {args.client_key}")
    if args.ca_cert:
        print(f"  CA cert:     {args.ca_cert}")
    print(f"  SSL verify:  {'yes' if not args.no_verify_ssl else 'no'}")
    print(f"  Proxy:       {'bypassed (-no-proxy)' if args.no_proxy else 'system default'}")
    print()

    PING_TIMEOUT = 10
    print(f"  Probing endpoints:")

    # --- REST probes ----------------------------------------------------
    # Probe v1 status, v2 status, and the Management profiles endpoint
    # (v2/endentity/profiles/authorized/ is the same probe used by
    # _auto_detect_backend, and is the canonical CE-vs-EE signal).
    rest_probes = [
        ("REST", "/v1/endentity/status"),
        ("REST", "/v2/endentity/status"),
        ("REST", "/v2/endentity/profiles/authorized/"),
    ]
    # Track which probes failed with TLS-verify so we can synthesise an
    # end-of-run summary if the *whole* run is one wrong-port confusion.
    rest_results: list[tuple[str, str, int | None, str]] = []
    tls_verify_failures = 0
    total_probe_count = len(rest_probes) + 1  # +1 for the SOAP probe below
    for kind, path in rest_probes:
        try:
            resp = client._request("GET", path,
                                   log_errors=False, timeout=PING_TIMEOUT)
        except requests.exceptions.Timeout:
            rest_results.append((kind, path, None, "TIMEOUT"))
            print(f"    {kind:5s} {path:48s}  TIMEOUT after {PING_TIMEOUT}s")
            continue
        except requests.exceptions.SSLError as e:
            if _is_tls_verify_error(e):
                tls_verify_failures += 1
                rest_results.append((kind, path, None, "TLS_VERIFY_FAILED"))
                print(f"    {kind:5s} {path:48s}  TLS verify failed")
                diag = _diagnose_tls_verify(args.ejbca_host, args.ejbca_port)
                for line in _format_tls_diag_line(diag):
                    print(line)
            else:
                rest_results.append((kind, path, None, f"SSL_ERROR: {e}"))
                print(f"    {kind:5s} {path:48s}  SSL error: {e}")
            continue
        except Exception as e:
            rest_results.append((kind, path, None, f"ERROR: {e}"))
            print(f"    {kind:5s} {path:48s}  ERROR: {e}")
            continue
        note = ""
        if resp.status_code == 200:
            try:
                body = resp.json()
                if isinstance(body, dict):
                    if "version" in body:
                        note = f"  {body.get('version')}"
                    elif "status" in body:
                        note = f"  status={body.get('status')}"
                    elif "end_entity_profiles" in body or \
                         "end_entitie_profiles" in body:
                        n = len(body.get("end_entity_profiles")
                                or body.get("end_entitie_profiles") or [])
                        note = f"  {n} profile(s)"
            except Exception:
                pass
        rest_results.append((kind, path, resp.status_code, note))
        print(f"    {kind:5s} {path:48s}  HTTP {resp.status_code}{note}")

    # --- SOAP probe -----------------------------------------------------
    # Call getEjbcaVersion via the SOAP backend. This is the cheapest SOAP
    # operation in the WSDL and confirms WS endpoint reachability + that
    # mTLS satisfied the SOAP-side ProtectedConnection check.
    soap_endpoint = "ejbcaws getEjbcaVersion"
    soap_status: str  # "OK", "ERROR", "SKIPPED"
    soap_note: str
    try:
        # Reuse the attached SOAP backend if _attach_ee_backend already
        # constructed one; otherwise build a transient one just for the probe.
        backend = getattr(client, "_ee_backend", None)
        if backend is None:
            backend = EjbcaSoapBackend(
                host=args.ejbca_host,
                port=args.ejbca_port,
                client_cert=args.client_cert,
                client_key=getattr(args, "client_key", None),
                ca_cert=args.ca_cert,
                verify_ssl=not args.no_verify_ssl,
                no_proxy=args.no_proxy,
            )
        version_str = backend._svc.getEjbcaVersion()
        soap_status = "OK"
        soap_note = f"  {version_str}" if version_str else ""
        print(f"    SOAP  {soap_endpoint:48s}  OK{soap_note}")
    except ImportError as e:
        # zeep not installed — can't probe SOAP at all.
        soap_status = "SKIPPED"
        soap_note = "zeep not installed"
        print(f"    SOAP  {soap_endpoint:48s}  SKIPPED ({soap_note})")
    except Exception as e:
        if _is_tls_verify_error(e):
            tls_verify_failures += 1
            soap_status = "TLS_VERIFY_FAILED"
            soap_note = "TLS verify failed"
            print(f"    SOAP  {soap_endpoint:48s}  TLS verify failed")
            diag = _diagnose_tls_verify(args.ejbca_host, args.ejbca_port)
            for line in _format_tls_diag_line(diag):
                print(line)
        else:
            soap_status = "ERROR"
            # No length-truncation: SOAP/zeep exceptions are often long but
            # all of it matters for debugging. v5.0.0 used [:120] and cut
            # mid-clause at "Caused b"; removed.
            soap_note = str(e).splitlines()[0]
            print(f"    SOAP  {soap_endpoint:48s}  ERROR: {soap_note}")

    # --- Synthesise verdict --------------------------------------------
    rest_codes = [code for _, _, code, _ in rest_results if code is not None]
    rest_200 = any(c == 200 for c in rest_codes)
    rest_all_404 = bool(rest_codes) and all(c == 404 for c in rest_codes)
    soap_ok = soap_status == "OK"

    print()
    if rest_200:
        print(f"  Result: OK  —  EJBCA EE detected (REST End Entity API available)")
        rc = 0
    elif rest_all_404 and soap_ok:
        # Fix 5: this is the CE signature, not a failure.
        print(f"  Result: OK  —  EJBCA CE detected "
              f"(REST EE API absent, SOAP available)")
        rc = 0
    elif soap_ok:
        # REST didn't cleanly 404 (maybe 401/500) but SOAP works.
        print(f"  Result: OK  —  SOAP available; REST surface degraded "
              f"(see per-endpoint lines above)")
        rc = 0
    elif rest_codes and not soap_ok:
        print(f"  Result: PARTIAL  —  REST reachable but no working EE API; "
              f"SOAP unreachable")
        rc = 1
    elif tls_verify_failures == total_probe_count:
        # Fix 7: every probe was rejected by the same wrong cert. This is
        # almost always a wrong-port or wrong-CA configuration, not an
        # EJBCA problem — and the underlying urllib3 message ("self-signed
        # certificate") misleads the user into looking at their CA file.
        diag = _diagnose_tls_verify(args.ejbca_host, args.ejbca_port)
        print(f"  Result: FAILED  —  TLS verify failed on every probe")
        print(f"  Hint:   nothing at {args.ejbca_host}:{args.ejbca_port} "
              f"presented a cert that chains to the configured CA.")
        if diag.get("available") and diag.get("subject"):
            print(f"          Presented cert:  {diag['subject']}")
            print(f"          Issued by:       {diag['issuer']}")
            print(f"          Expected CA:     {args.ca_cert or '(system trust store)'}")
        print(f"          Likely cause:    wrong port (something else is on "
              f"{args.ejbca_port}),")
        print(f"                           or the EJBCA server cert was "
              f"reissued by a different CA,")
        print(f"                           or -ca-cert / ELT_CA_CERT points "
              f"at the wrong file.")
        rc = 1
    else:
        print(f"  Result: FAILED  —  no API surface reachable")
        rc = 1
    print()

    # With -v: test END_ENTITY_PROFILE search criterion
    if getattr(args, "verbose", 0) >= 1:
        _test_ee_profile_criterion(client)

    if rc != 0:
        sys.exit(rc)


def _test_ee_profile_criterion(client: EjbcaClient):
    """
    Test whether END_ENTITY_PROFILE can be used as a search criterion.
    Auto-fetches the first authorised profile name via the profiles endpoint.
    Validates vendor claim that the profile name (not ID) is required.
    Reports result clearly for documentation purposes.
    """
    print(f"  {'=' * 74}")
    print(f"  Test: END_ENTITY_PROFILE search criterion")
    print(f"  Vendor claim: use profile name (not numeric ID) as criterion value")
    print()

    # Auto-fetch first authorised profile name
    resp_prof = client._request("GET", "/v2/endentity/profiles/authorized",
                                log_errors=False)
    profile_name = None
    if resp_prof.status_code == 200:
        data = resp_prof.json()
        profiles = (data.get("end_entity_profiles")
                    or data.get("end_entitie_profiles") or [])
        if profiles:
            profile_name = profiles[0].get("name")
    if not profile_name:
        print(f"  Could not fetch authorised profile list "
              f"(HTTP {resp_prof.status_code}) — skipping test")
        print()
        return
    print(f"  Profile name: {profile_name}  (first from authorized list)")
    print()

    for version, endpoint in (("v2", "/v2/endentity/search"),
                               ("v1", "/v1/endentity/search")):
        payload_name = {
            "max_number_of_results": 5,
            "current_page": 1,
            "criteria": [{
                "property": "END_ENTITY_PROFILE",
                "value": profile_name,
                "operation": "EQUAL",
            }],
            "sort_operation": {"property": "USERNAME", "operation": "ASC"},
        }
        resp_name = client._request("POST", endpoint,
                                    log_errors=False, json=payload_name)
        n_name = 0
        if resp_name.status_code == 200:
            n_name = len(resp_name.json().get("end_entities", []))
            verdict_name = f"OK — {n_name} entit{'y' if n_name == 1 else 'ies'} returned"
        else:
            try:
                msg = resp_name.json().get("error_message", resp_name.text[:120])
            except Exception:
                msg = resp_name.text[:120]
            verdict_name = f"HTTP {resp_name.status_code} — {msg}"

        print(f"  {version} / name:  {verdict_name}")

    print()
    if resp_name.status_code == 200 and n_name >= 0:
        print(f"  Conclusion: vendor claim CONFIRMED — profile name works as criterion")
        print(f"  Consider switching search_all_end_entities() to use "
              f"END_ENTITY_PROFILE criterion directly (performance improvement).")
    else:
        print(f"  Conclusion: vendor claim NOT CONFIRMED — criterion still rejected")
        print(f"  Issue 10 in JohnB-ejbca-fix-requests.md remains valid.")
    print()


# ---------------------------------------------------------------------------
# Count mode
# ---------------------------------------------------------------------------

def find_ghost_usernames(client: EjbcaClient,
                         max_ee: int = 500,
                         max_certs: int = 10000) -> dict[str, list]:
    """
    Detect ghost EE usernames: usernames that appear in certificate records
    but have no corresponding live EE record in EJBCA.

    Returns dict: {username: [cert, ...]} for each ghost username found.
    The cert list is sorted newest-first (by notBefore).
    """
    log.info("Ghost detection: fetching all live EE usernames...")
    live_ees = client.search_all_end_entities(max_results=max_ee)
    live_usernames = {ee.get("username", "") for ee in live_ees}
    log.info(f"  Live EEs: {len(live_usernames)}")

    log.info("Ghost detection: fetching all certificate records...")
    all_certs = client.search_certificates_v2(
        criteria=[{"property": "QUERY", "value": "%", "operation": "LIKE"}],
        max_results=max_certs,
    )
    log.info(f"  Cert records: {len(all_certs)}")

    # Group certs by username, keeping only those not in live EE set
    ghost_map: dict[str, list] = {}
    for cert in all_certs:
        uname = cert.get("username", "")
        if not uname or uname in live_usernames:
            continue
        ghost_map.setdefault(uname, []).append(cert)

    # Sort certs within each ghost newest-first
    for uname in ghost_map:
        ghost_map[uname].sort(
            key=lambda c: c.get("notBefore", ""), reverse=True)

    log.info(f"  Ghost usernames detected: {len(ghost_map)}")
    return ghost_map


def cmd_count(args, client: EjbcaClient):
    """Certificate count overview: global totals + per-EE breakdown."""

    if args.cert_detail > 0:
        log.warning(f"-ci{args.cert_detail} ignored (not applicable to count)")

    # profile handled by args

    log.info("Certificate count overview")

    # Resolve profile filter
    profile_name, profile_id = _resolve_ee_profile(
        args.ee_profile, client)

    # Resolve sort field (default: active)
    sort_field = args.sort_field or "active"

    # Part 1: Global certificate counts from API
    print(f"\n{'=' * 78}")
    print(f"EJBCA Certificate Count Overview:  count")
    if profile_name:
        print(f"EE Profile:    {profile_name}")
    if args.ee_username:
        print(f"EE Username:   {args.ee_username}")
    if not profile_name and not args.ee_username:
        print(f"EE Profile:    (all)")
    if args.cert_cn:
        print(f"Cert CN:       {args.cert_cn}")
    if args.cert_serial:
        print(f"Cert Serial:   {args.cert_serial}")
    if args.k8s_status:
        print(f"K8s Status:    {args.k8s_status}")
    elif args.k8s_compare:
        print(f"K8s Compare:   enabled")
    print(f"Sorted by:     {sort_field}")
    print(f"Generated:     {datetime.now(timezone.utc).isoformat()}")
    print(f"Host:          {args.ejbca_host}:{args.ejbca_port}")
    print(f"{'=' * 78}")
    sys.stdout.flush()
    print("  ... querying EJBCA REST API ...")

    count_all = client.get_certificate_count(is_active=None)
    count_active = client.get_certificate_count(is_active=True)

    print(f"\n  Global certificate counts (from EJBCA API):")
    print(f"  (includes CA certs, management certs, ghost certs from deleted EEs,")
    print(f"   and other system certs without end-entities)")
    print()
    if count_all == -403:
        print(f"    (access denied — role needs "
              f"/system_functionality/view_systemconfiguration/)")
        print(f"    Check: Is your $ELT_CERT added as a role member associated with RA access rules?")
        print(f"    Check: Is the CA of your $ELT_CERT added to the TRUSTED CA list?")
    elif count_all is not None and count_all >= 0:
        print(f"    Total:     {count_all:>6d}")
        if count_active is not None and count_active >= 0:
            print(f"    Active:    {count_active:>6d}")
            inactive = count_all - count_active
            print(f"    Inactive:  {inactive:>6d}")
    else:
        print(f"    Total:     (endpoint unavailable)")
    sys.stdout.flush()

    # Part 2: Per-EE breakdown
    # Fetch K8s identities if requested
    k8s_identities = None
    if args.k8s_compare:
        log.info("Cross-referencing with Kubernetes cert-manager...")
        cm_certs = get_certmanager_certificates(kubectl_cmd=args.kubectl)
        k8s_identities = build_k8s_identity_set(cm_certs)

    def _compute_k8s_tag(ee_name, ee_data=None):
        """Compute K8s status tag for one EE."""
        if k8s_identities is None:
            return ""
        is_orphaned = ee_name.lower() not in k8s_identities
        if is_orphaned and ee_data:
            for rdn in _split_dn(ee_data.get("dn", "")):
                cn_val = _rdn_cn_value(rdn)
                if cn_val and cn_val.lower() in k8s_identities:
                    return "active"
        return "orphaned" if is_orphaned else "active"

    # Single-EE mode
    k8s_filtered = 0
    if args.ee_username:
        certs = client.search_certs_for_username(
            args.ee_username, max_results=args.max_certs)
        certs = _filter_certs(certs,
                              cert_cn=getattr(args, "cert_cn", None),
                              cert_serial=getattr(args, "cert_serial", None))
        n_certs = len(certs)
        active, expired, revoked_exp, revoked_unexp, _other = _summarize_cert_counts(certs)
        revoked = revoked_exp + revoked_unexp
        # Try to find the EE profile from cert data
        p_display = "(unknown)"
        if certs:
            p_display = certs[0].get("endEntityProfile", "") or "(orphans)"
        k8s_tag = _compute_k8s_tag(args.ee_username)
        row = (n_certs, active, expired, revoked, p_display,
               args.ee_username, k8s_tag)
        if args.k8s_status:
            if args.k8s_status != k8s_tag:
                rows = []
                k8s_filtered = 1
            else:
                rows = [row]
        else:
            rows = [row]
        skipped = 0
    else:
        # All EEs mode
        end_entities = client.search_all_end_entities(
            max_results=args.max_end_entities,
            status_filter=args.status_filter,
        )

        if not end_entities:
            print("\n  No End Entities found.")
            print(f"\n{'-' * 78}")
            print()
            return

        # Enrich with profile data
        profile_map = client.build_profile_map(max_results=args.max_certs)
        client.enrich_end_entities(end_entities, profile_map)

        # Build per-EE cert counts
        rows = []
        skipped = 0
        n_to_query = len(end_entities)
        print(f"\n  Querying {n_to_query} end entities for certificate counts...")
        sys.stdout.flush()
        for ee in end_entities:
            ee_name = ee.get("username", ee.get("name", "unknown"))
            ee_profile = ee.get("endEntityProfile", "")
            ee_profile_id = ee.get("endEntityProfileId")

            if not _profile_matches(ee_profile, ee_profile_id,
                                    profile_name, profile_id):
                skipped += 1
                continue

            # K8s filter (before cert API call for performance)
            k8s_tag = _compute_k8s_tag(ee_name, ee)
            if args.k8s_status:
                if args.k8s_status != k8s_tag:
                    k8s_filtered += 1
                    continue

            certs = client.search_certs_for_username(ee_name, max_results=args.max_certs)
            certs = _filter_certs(certs,
                                  cert_cn=getattr(args, "cert_cn", None),
                                  cert_serial=getattr(args, "cert_serial", None))
            n_certs = len(certs)
            if (args.cert_cn or args.cert_serial) and n_certs == 0:
                continue
            active, expired, revoked_exp, revoked_unexp, _other = _summarize_cert_counts(certs)
            revoked = revoked_exp + revoked_unexp
            p_display = ee_profile or "(orphans)"
            rows.append((n_certs, active, expired, revoked,
                         p_display, ee_name, k8s_tag))

    # Sort: primary key from -sort (desc), then profile asc, username asc.
    # Row layout: (total, active, expired, revoked, profile, username, k8s).
    _sort_idx = {"total": 0, "active": 1, "expired": 2, "revoked": 3}
    _sk = _sort_idx[sort_field]
    rows.sort(key=lambda r: (-r[_sk], r[4].lower(), r[5].lower()))

    # Compute column widths
    if rows:
        prof_w = max(len(r[4]) for r in rows)
        prof_w = max(prof_w, len("EE Profile"))
        name_w = max(len(r[5]) for r in rows)
        name_w = max(name_w, len("EE Username"))
    else:
        prof_w = len("EE Profile")
        name_w = len("EE Username")

    # Print table
    total_certs = sum(r[0] for r in rows)
    total_active = sum(r[1] for r in rows)
    total_expired = sum(r[2] for r in rows)
    total_revoked = sum(r[3] for r in rows)
    has_cert_filter = getattr(args, "cert_cn", None) or getattr(args, "cert_serial", None)
    show_k8s = args.k8s_compare

    if has_cert_filter and not rows:
        print(f"\n  No matching certificates found.")
        if skipped:
            print(f"\n  Skipped (other EE profiles): {skipped}")
        if k8s_filtered:
            print(f"\n  Filtered (-k8s-status): {k8s_filtered}")
        print(f"\n{'-' * 78}")
        print()
        return

    if args.k8s_status and not rows:
        print(f"\n  No End Entities matched -k8s-status {args.k8s_status}.")
        if skipped:
            print(f"\n  Skipped (other EE profiles): {skipped}")
        if k8s_filtered:
            print(f"\n  Filtered (-k8s-status): {k8s_filtered}")
        print(f"\n{'-' * 78}")
        print()
        return

    print(f"  Per End Entity ({len(rows)} EEs, {total_certs} certs):")
    print(f"  Sorted by: {sort_field}")
    print()
    k8s_col = f"  {'K8s':<7s}" if show_k8s else ""
    k8s_sep = f"  {'-------'}" if show_k8s else ""
    hdr = (f"  {'Total':>6s}  {'Active':>6s}  {'Expired':>7s}  {'Revoked':>7s}"
           f"{k8s_col}"
           f"  {' EE Profile':<{prof_w + 1}s}"
           f"  {'EE Username':<{name_w}s}")
    print(hdr)
    print(f"  {'------':>6s}  {'------':>6s}  {'-------':>7s}  {'-------':>7s}"
          f"{k8s_sep}"
          f"  {'-' * prof_w}-"
          f"  {'-' * name_w}")

    for n_certs, active, expired, revoked, profile, username, k8s_tag in rows:
        k8s_short = k8s_tag.replace("orphaned", "orphan") if k8s_tag else ""
        k8s_val = f"  {k8s_short:<7s}" if show_k8s else ""
        print(f"  {n_certs:>6d}  {active:>6d}  {expired:>7d}  {revoked:>7d}"
              f"{k8s_val}"
              f"  {' ' + profile:<{prof_w + 1}s}"
              f"  {username:<{name_w}s}")

    if not has_cert_filter and not args.k8s_status:
        print()
        print(f"  {'------':>6s}  {'------':>6s}"
              f"  {'-------':>7s}  {'-------':>7s}")
        print(f"  {total_certs:>6d}  {total_active:>6d}"
              f"  {total_expired:>7d}  {total_revoked:>7d}"
              f"  (total)")

    if skipped:
        print(f"\n  Skipped (other EE profiles): {skipped}")
    if k8s_filtered:
        print(f"  Filtered (-k8s-status): {k8s_filtered}")

    # Ghost summary
    if getattr(args, "ghosts", False):
        ghost_map = find_ghost_usernames(
            client,
            max_ee=args.max_end_entities,
            max_certs=args.max_certs,
        )
        print()
        if ghost_map:
            print(f"  Ghost EE usernames (cert records outliving deleted EE): "
                  f"{len(ghost_map)}")
            print()
            # Column header
            _uw = max((len(u) for u in ghost_map), default=11)
            _uw = max(_uw, len("EE Username"))
            print(f"    {'EE Username':<{_uw}s}  Counts")
            print(f"    {'-' * _uw}  -------")
            for _u in sorted(ghost_map):
                _certs = ghost_map[_u]
                _a, _e, _re, _ru, _o = _summarize_cert_counts(_certs)
                print(f"    {_u:<{_uw}s}  "
                      f"{_format_cert_breakdown(_a, _e, _re, _ru, _o)}")
            print()
            print(f"  Run: elt list4 -ghosts   for full details")
        else:
            print(f"  Ghost EE usernames: none detected")
    print()


# ---------------------------------------------------------------------------
# Cert-List mode
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Cert-List mode
# ---------------------------------------------------------------------------

def _filter_certs(certs: list, cert_cn: str = None,
                  cert_serial: str = None) -> list:
    """Filter a list of cert dicts by CN substring and/or serial substring."""
    if not cert_cn and not cert_serial:
        return certs
    filtered = []
    # Normalize serial search: strip colons for comparison
    serial_search = cert_serial.replace(":", "").lower() if cert_serial else ""
    for cert in certs:
        if cert_cn:
            subject = cert.get("subjectDN", "")
            # Extract CN from subject DN
            cn_val = ""
            for rdn in _split_dn(subject):
                rdn = rdn.strip()
                cn_val_check = _rdn_cn_value(rdn)
                if cn_val_check:
                    cn_val = cn_val_check
                    break
            if cert_cn.lower() not in cn_val.lower():
                continue
        if serial_search:
            raw_serial = (cert.get("serialNumber", "")
                          .replace(":", "").lower())
            if serial_search not in raw_serial:
                continue
        filtered.append(cert)
    return filtered


def _print_ee_cert_table(client: EjbcaClient, username: str,
                         max_certs: int, show_profile: bool = True,
                         show_header: bool = True,
                         show_full: bool = False,
                         cert_profile_override: str = "",
                         ee_data: dict = None,
                         is_ghost: bool = False,
                         cert_cn: str = None,
                         cert_serial: str = None,
                         k8s_status: str = "",
                         cert_detail: int = 0,
                         active_only: bool = False,
                         revoked_only: bool = False) -> int:
    """Print cert block for one EE. Returns cert count (after filtering).

    show_profile: if False, skip profile header (shown in banner).
    cert_profile_override: if set, show this cert profile per-entry.
    ee_data: if provided, show EE-level fields (status, token, email, key).
    cert_cn: if set, filter certs by CN substring match.
    cert_serial: if set, filter certs by serial substring match.
    k8s_status: if set, display K8s status line.
    cert_detail: 0=compact table, 1=block+CN, 2=block+full DN.
    active_only: if True, drop revoked AND expired rows from the cert table.
    revoked_only: if True, drop active AND expired rows from the cert table.
    show_full: if False (default), truncate cert list at 10 rows.
    """
    CERT_DISPLAY_LIMIT = 10
    certs = client.search_certs_for_username(username, max_results=max_certs)
    all_count = len(certs)

    # Apply cert filters
    certs = _filter_certs(certs, cert_cn=cert_cn, cert_serial=cert_serial)
    # Apply status filter (-active / -revoked) on the cert table itself.
    # Done AFTER count summary so the summary still reflects the EE's
    # full population; the table just shows the filtered subset.
    if active_only:
        certs_for_table = [c for c in certs if _is_cert_active(c)]
    elif revoked_only:
        certs_for_table = [c for c in certs if _is_cert_revoked(c)]
    else:
        certs_for_table = certs
    n_certs = len(certs)
    n_table = len(certs_for_table)

    # If filtering and no matches, skip this EE entirely
    if (cert_cn or cert_serial) and n_certs == 0:
        return 0

    if all_count == 0:
        print(f"\n  EE Username:   {username}")
        print(f"  (no certificates)")
        return 0

    active, expired, revoked_exp, revoked_unexp, _other = _summarize_cert_counts(certs)
    revoked = revoked_exp + revoked_unexp

    if show_header:
        print(f"\n  EE Username:   {username}")
        if is_ghost:
            print(f"  EE Status:     "
                  f"*** GHOST — EE deleted; certificate records persist until expiry ***")
    if k8s_status:
        print(f"  K8s Status:    {k8s_status}")
    if cert_profile_override:
        print(f"  Cert Profile:  {cert_profile_override}")

    if show_profile:
        sample = certs[0]
        ee_profile = sample.get("endEntityProfile", "")
        cert_profile = sample.get("certificateProfile", "")

        print(f"  EE Profile:    {ee_profile or '(orphans)'}")
        if cert_profile:
            print(f"  Cert Profile:  {cert_profile}")

    # Show EE-level fields if available
    if ee_data:
        ee_status = ee_data.get("status", "")
        ee_token = ee_data.get("token", "")
        ee_email = ee_data.get("email", "")
        if ee_status:
            print(f"  EE Status:     {ee_status}")
        if ee_token:
            print(f"  EE Token:      {ee_token}")
        if ee_email:
            print(f"  Email:         {ee_email}")
        # Key algorithm from extension_data
        ext_data = ee_data.get("extension_data")
        key_alg = ""
        key_sub = ""
        if isinstance(ext_data, list):
            for ext in ext_data:
                if not isinstance(ext, dict):
                    continue
                if ext.get("name") == "KEYSTORE_ALGORITHM_TYPE":
                    key_alg = ext.get("value", "")
                elif ext.get("name") == "KEYSTORE_ALGORITHM_SUBTYPE":
                    key_sub = ext.get("value", "")
        if key_alg:
            alg_str = f"{key_alg} {key_sub}".strip() if key_sub else key_alg
            print(f"  Key Algorithm: (EJBCA generated) {alg_str}")
        else:
            print(f"  Key Algorithm: (user supplied)")

    is_filtered = (cert_cn or cert_serial) and n_certs < all_count
    if show_header:
        print()
        if is_filtered:
            print(f"  Certificates:  {n_certs} of {all_count} matched:  "
                  f"{_format_cert_breakdown(active, expired, revoked_exp, revoked_unexp)}")
        else:
            print(f"  Certificates:  {n_certs}:  "
                  f"{_format_cert_breakdown(active, expired, revoked_exp, revoked_unexp)}")
        _print_cert_status_hints(revoked_unexp)

    # ---------- cert_detail == 0: compact table ----------
    if cert_detail == 0:
        # Compute CN column width using only what we'll display.
        cn_vals = []
        for cert in certs_for_table:
            cn_vals.append(_extract_cn(cert.get("subjectDN", "")))
        cn_w = max((len(c) for c in cn_vals), default=2)
        cn_w = max(cn_w, 2)  # minimum "CN" header width

        print()
        print(f"{'#':>4s}  S  {'Serial':<40s}  {'Not Before':<24s}  "
              f"{'Not After':<24s}  {'CN':<{cn_w}s}")
        print(f"{'----':>4s}  -  {'-' * 40}  {'-' * 24}  "
              f"{'-' * 24}  {'-' * cn_w}")

        display_certs = (certs_for_table if show_full
                         else certs_for_table[:CERT_DISPLAY_LIMIT])
        for i, cert in enumerate(display_certs, 1):
            # 4-state status: A active, E expired, R revoked+expired,
            # r revoked+unexpired, ? unknown.
            s_flag = _cert_flag(cert)
            serial_raw = cert.get("serialNumber", "").lower()
            not_before = _format_cert_time(cert.get("notBefore"))
            not_after = _format_cert_time(cert.get("expireDate"))
            cn = _extract_cn(cert.get("subjectDN", ""))
            print(f"{i:>4d}  {s_flag}  {serial_raw:<40s}  "
                  f"{not_before:<24s}  {not_after:<24s}  {cn}")
        if not show_full and n_table > CERT_DISPLAY_LIMIT:
            print(f"  ... {n_table - CERT_DISPLAY_LIMIT} more"
                  f" — use -F to see the full list")
        if (active_only or revoked_only) and n_table < n_certs:
            kept_label = "active" if active_only else "revoked"
            print(f"  ({n_certs - n_table} of {n_certs} certs hidden"
                  f" — table filtered to {kept_label} only)")

    # ---------- cert_detail >= 1: block format ----------
    else:
        full_dn = (cert_detail >= 2)
        display_certs = (certs_for_table if show_full
                         else certs_for_table[:CERT_DISPLAY_LIMIT])
        for i, cert in enumerate(display_certs, 1):
            issuer = cert.get("issuerDN", "")
            subject = cert.get("subjectDN", "")
            serial = _format_serial(cert.get("serialNumber", ""))
            not_before = _format_cert_time(cert.get("notBefore"))
            not_after = _format_cert_time(cert.get("expireDate"))
            san = cert.get("subjectAltName", "")
            rev_reason = cert.get("revocationReason", "")
            rev_date = cert.get("revocationDate")
            log.debug(f"  cert serial={serial} status={cert.get('status')!r}")
            status_tag = _single_cert_label(cert)

            if n_table == 1:
                print(f"\n  -- certificate : {status_tag} --")
            else:
                print(f"\n  -- certificate {i}: {status_tag} --")
            if issuer:
                print(f"    Issuer:          {_format_dn_display(issuer, full_dn)}")
            if subject:
                print(f"    Subject:         {_format_dn_display(subject, full_dn)}")
            print(f"      Serial Number:   {serial}")
            print(f"      Not Before:      {not_before}")
            print(f"      Not After:       {not_after}")
            print(f"    SAN:             {san or '(none)'}")
            if _is_cert_revoked(cert):
                reason_str = rev_reason or "unknown"
                date_str = _format_cert_time(rev_date) if rev_date else "unknown"
                print(f"    Revoked:         {reason_str} ({date_str})")
        if not show_full and n_table > CERT_DISPLAY_LIMIT:
            print(f"\n  ... {n_table - CERT_DISPLAY_LIMIT} more"
                  f" — use -F to see the full list")
        if (active_only or revoked_only) and n_table < n_certs:
            kept_label = "active" if active_only else "revoked"
            print(f"\n  ({n_certs - n_table} of {n_certs} certs hidden"
                  f" — table filtered to {kept_label} only)")

    print()
    sys.stdout.flush()
    return n_certs



# ---------------------------------------------------------------------------
# Cleanup mode
# ---------------------------------------------------------------------------

def cmd_cleanup(args, client: EjbcaClient):
    """Execute cleanup mode: revoke and optionally delete orphaned End Entities."""

    if args.cert_detail > 0:
        log.warning(f"-ci{args.cert_detail} ignored (not applicable to cleanup)")
    if args.cert_cn:
        log.warning("-cert-cn ignored (not applicable to cleanup)")
    if args.cert_serial:
        log.warning("-cert-serial ignored (not applicable to cleanup)")
    if args.k8s_status:
        log.warning("-k8s-status ignored (not applicable to cleanup; "
                     "use -k8s-compare instead)")
    if getattr(args, "sort_field", None) is not None:
        log.warning("-sort ignored (only applies to count)")

    if args.commit:
        args.dry_run = False
    elif not args.dry_run:
        args.dry_run = True
        log.info("No -confirm flag; defaulting to --dry-run mode")

    # Resolve -keep-newest default:
    #   --delete-ee alone -> implicitly revoke all (keep=0) then delete
    #   plain cleanup     -> default keep=1 (existing behaviour)
    if args.keep_newest is None:
        args.keep_newest = 0 if args.delete_ee else 1

    # Route to -keep-newest mode
    if args.keep_newest is not None:
        _cleanup_keep_newest(args, client)
        return

    log.info(f"Cleanup mode ({'DRY RUN' if args.dry_run else 'COMMIT'})")

    profile_name, profile_id = _resolve_ee_profile(
        args.ee_profile, client)

    end_entities = client.search_all_end_entities(
        max_results=args.max_end_entities,
        status_filter=args.status_filter,
    )
    log.info(f"Found {len(end_entities)} End Entities")

    if not end_entities:
        print("No End Entities found matching criteria. Nothing to clean up.")
        return

    profile_map = client.build_profile_map(max_results=args.max_certs)
    client.enrich_end_entities(end_entities, profile_map)

    if profile_name or profile_id:
        before = len(end_entities)
        filtered = []
        for ee in end_entities:
            ee_profile = ee.get("endEntityProfile", "")
            ee_profile_id = ee.get("endEntityProfileId")
            if not _profile_matches(ee_profile, ee_profile_id,
                                    profile_name, profile_id):
                continue
            filtered.append(ee)
        end_entities = filtered
        log.info(f"After profile filter: {len(end_entities)}/{before} entities")

    if not end_entities:
        print("No End Entities found matching criteria. Nothing to clean up.")
        return

    # Determine which EEs to clean up
    targets = []

    if args.ee_username:
        # Single EE mode — no -all or -k8s-compare needed
        targets = [args.ee_username]

    elif args.k8s_compare:
        log.info("Cross-referencing with Kubernetes cert-manager...")
        cm_certs = get_certmanager_certificates(kubectl_cmd=args.kubectl)
        k8s_identities = build_k8s_identity_set(cm_certs)
        log.info(f"Found {len(k8s_identities)} active K8s identities")

        for ee in end_entities:
            ee_name = ee.get("username", ee.get("name", "unknown"))
            ee_dn = ee.get("dn", ee.get("subject_dn", ""))
            is_orphaned = ee_name.lower() not in k8s_identities
            if is_orphaned and ee_dn:
                for rdn in _split_dn(ee_dn):
                    cn_val = _rdn_cn_value(rdn)
                    if cn_val and cn_val.lower() in k8s_identities:
                            is_orphaned = False
                            break
            if is_orphaned:
                targets.append(ee_name)
    else:
        if not args.all_matching:
            log.error("Without -ee-username or -k8s-compare, you must pass "
                      "-all to confirm you want to operate on ALL matching "
                      "End Entities.")
            sys.exit(1)
        targets = [ee.get("username", ee.get("name", "unknown"))
                    for ee in end_entities]

    if not targets:
        print("No orphaned End Entities found. Nothing to clean up.")
        print()
        return

    print(f"\n{'DRY RUN — ' if args.dry_run else ''}Cleanup targets "
          f"({len(targets)} End Entities):")
    for name in targets:
        print(f"  - {name}")

    if args.dry_run:
        if args.delete_ee:
            print(f"\nDRY RUN: Would delete {len(targets)} End Entities "
                  f"(no revocation — certs stay valid until expiry)")
        else:
            print(f"\nDRY RUN: Would revoke {len(targets)} End Entities "
                  f"(reason: {args.revoke_reason})")
            if args.delete_after_revoke:
                print(f"DRY RUN: Would then delete {len(targets)} End Entities")
        print("To execute, re-run with -commit")
        print()
        return

    # Validate flag conflicts
    if args.delete_ee and args.delete_after_revoke:
        log.error("--delete-ee and --delete-after-revoke are mutually exclusive.")
        sys.exit(1)

    # Execute cleanup
    revoked = 0
    deleted = 0
    errors = 0

    for ee_name in targets:
        log.info(f"Processing: {ee_name}")

        if args.delete_ee:
            if client.delete_end_entity(ee_name):
                deleted += 1
            else:
                errors += 1
                log.warning(f"Failed to delete: {ee_name}")
        else:
            if client.revoke_end_entity(ee_name, reason=args.revoke_reason):
                revoked += 1
                if args.delete_after_revoke:
                    if client.delete_end_entity(ee_name):
                        deleted += 1
                    else:
                        errors += 1
                        log.warning(f"Revoked but failed to delete: {ee_name}")
            else:
                errors += 1

    # Summary
    print(f"\n{'=' * 60}")
    print(f"Cleanup Summary")
    print(f"{'=' * 60}")
    print(f"Targets:  {len(targets)}")
    if not args.delete_ee:
        print(f"Revoked:  {revoked}")
    print(f"Deleted:  {deleted}")
    print(f"Errors:   {errors}")
    if args.delete_ee:
        print(f"Note:     Certs not revoked (--delete-ee)")
    print(f"{'=' * 60}")
    print()


def _cleanup_keep_newest(args, client: EjbcaClient):
    """Per-certificate cleanup: revoke all but the newest N certs per EE.

    The End Entity is kept intact. Only individual certificates are revoked.
    Already-revoked certificates are skipped.
    """
    keep = args.keep_newest
    if keep < 0:
        log.error("-keep-newest must be 0 or higher")
        sys.exit(1)

    is_dry = not args.commit
    mode_str = "DRY RUN" if is_dry else "COMMIT"
    log.info(f"Cleanup -keep-newest {keep} ({mode_str})")

    profile_name, profile_id = _resolve_ee_profile(
        args.ee_profile, client)

    # Banner
    print(f"\n{'=' * 78}")
    if keep == 0:
        print(f"EJBCA Cert Cleanup — revoke ALL certs per EE:  "
              f"cleanup -keep-newest 0")
    else:
        print(f"EJBCA Cert Cleanup — keep newest {keep} per EE:  "
              f"cleanup -keep-newest {keep}")
    if profile_name:
        print(f"EE Profile:    {profile_name}")
    elif args.ee_username:
        print(f"EE Username:   {args.ee_username}")
    else:
        print(f"EE Profile:    (all)")
    print(f"Mode:          {mode_str}")
    print(f"Revoke reason: {args.revoke_reason}")
    print(f"{'=' * 78}")
    sys.stdout.flush()
    print("  ... querying EJBCA REST API ...")

    # Build EE target list
    if args.ee_username:
        # Single EE mode
        ee_names = [args.ee_username]
    else:
        end_entities = client.search_all_end_entities(
            max_results=args.max_end_entities,
            status_filter=args.status_filter,
        )
        if not end_entities:
            print("\nNo End Entities found.")
            return

        profile_map = client.build_profile_map(max_results=args.max_certs)
        client.enrich_end_entities(end_entities, profile_map)

        # Filter by profile
        ee_names = []
        for ee in end_entities:
            ee_profile = ee.get("endEntityProfile", "")
            ee_profile_id = ee.get("endEntityProfileId")
            if profile_name or profile_id:
                if not _profile_matches(ee_profile, ee_profile_id,
                                        profile_name, profile_id):
                    continue
            ee_names.append(ee.get("username", ee.get("name", "unknown")))

        if not ee_names and not args.ee_username:
            if not args.all_matching and not profile_name and not profile_id:
                log.error("Without -ee-profile or -ee-username, you must "
                          "pass -all to confirm operation on ALL End Entities.")
                sys.exit(1)

    if not ee_names:
        print("\nNo End Entities matched. Nothing to clean up.")
        return

    # v5.0.0 fix 11: self-deletion guard. Refuse to operate on the EE that
    # owns the client cert ELT is currently authenticated as. Without this,
    # a broad cleanup with --delete-ee can delete its own admin EE and lock
    # the user out — recovery then requires container-side ejbca.sh.
    # Comparison is by Subject CN, which is robust to format variations
    # between openssl and EJBCA's DN serialisation.
    self_cn = _get_cert_cn(args.client_cert)
    if self_cn:
        # Build EE records list to look up DNs from. In multi-EE mode the
        # records were already fetched above; in single-EE mode we do a
        # targeted lookup so the guard still applies.
        ee_records_for_guard: list = []
        if args.ee_username:
            try:
                rec = client.search_end_entities(
                    [{"property": "USERNAME", "value": args.ee_username,
                      "operation": "EQUAL"}], max_results=1)
                if rec:
                    ee_records_for_guard = rec
            except Exception as e:
                log.debug(f"Self-guard EE lookup failed: {e}")
        else:
            # Multi-EE mode: end_entities is in scope from the else-branch above
            ee_records_for_guard = end_entities

        cn_by_name = {}
        for ee in ee_records_for_guard:
            uname = ee.get("username", ee.get("name", ""))
            cn = _extract_cn(ee.get("dn", ""))
            if uname and cn:
                cn_by_name[uname] = cn

        safe = []
        skipped_self: list[tuple[str, str]] = []
        for name in ee_names:
            ee_cn = cn_by_name.get(name)
            if ee_cn and ee_cn.lower() == self_cn.lower():
                skipped_self.append((name, ee_cn))
            else:
                safe.append(name)

        if skipped_self:
            print(f"\n{'!' * 78}")
            print(f"SELF-GUARD: refusing to revoke/delete the EE that "
                  f"authenticates this ELT session.")
            for name, cn in skipped_self:
                print(f"  skip:  {name}  (CN={cn} matches current ELT cert)")
            print(f"  hint:  use 'ejbca.sh' inside the container if you "
                  f"really need to remove this EE.")
            print(f"{'!' * 78}")
            ee_names = safe

        if not ee_names:
            print("\nNo End Entities left to clean up after self-guard.")
            return

    # v5.0.0 fix 10: typed-confirmation safety net for the wide-blast case.
    # Triggers when commit mode is on AND `-all` was used AND no single EE
    # was targeted (single-EE mode is already self-scoped). The dry-run
    # path stays unchanged, so the "dry-run first, then commit" workflow
    # gets safety on the second invocation too — not just the first.
    # Automation can pipe input via `echo yes | elt cleanup ...`.
    if args.commit and args.all_matching and not args.ee_username:
        scope = f"all {len(ee_names)} End Entit"
        scope += "y" if len(ee_names) == 1 else "ies"
        action = "delete" if args.delete_ee else (
            "revoke all active certs of" if keep == 0 else
            f"revoke all but the newest {keep} active cert(s) of"
        )
        print(f"\n{'!' * 78}")
        print(f"WARNING: about to {action} {scope}.")
        if args.delete_ee:
            print(f"         End Entity records will be DELETED — irreversible.")
        else:
            print(f"         Cert revocation is irreversible (reason: "
                  f"{args.revoke_reason}).")
        print(f"{'!' * 78}")
        try:
            reply = input("Type 'yes' to proceed (anything else aborts): ")
        except (EOFError, KeyboardInterrupt):
            reply = ""
        if reply.strip().lower() != "yes":
            print("\nAborted. Nothing was changed.")
            return
        print()

    # Process each EE
    total_revoked = 0
    total_skipped = 0
    total_already_revoked = 0
    total_kept = 0
    total_errors = 0
    ees_processed = 0
    ees_with_revocations = 0
    ees_to_delete = []  # populated when --delete-ee and all certs revoked

    for ee_name in ee_names:
        certs = client.search_certs_for_username(
            ee_name, max_results=args.max_certs)
        if not certs:
            # v5.0.0 fix 9: zero-cert EEs are eligible for deletion under
            # --delete-ee. The previous behaviour was a silent no-op — the
            # EE was scanned, no certs found, loop skipped to the next EE
            # without ever appending to ees_to_delete. That made
            # `cleanup --delete-ee` useless for the exact population
            # (orphan EEs with no certs) that's most worth deleting.
            if args.delete_ee:
                print(f"\n  EE Username:   {ee_name}")
                print(f"  Total certs:   0 (empty EE — eligible for deletion)")
                ees_to_delete.append(ee_name)
                sys.stdout.flush()
            continue

        # Split: active certs (newest first, already sorted) and revoked
        active_certs = [c for c in certs if not _is_cert_revoked(c)]
        already_revoked = len(certs) - len(active_certs)

        if len(active_certs) <= keep:
            # Nothing to revoke for this EE
            total_kept += len(active_certs)
            total_already_revoked += already_revoked
            # EE eligible for deletion if no active certs remain
            if args.delete_ee and len(active_certs) == 0:
                ees_to_delete.append(ee_name)
            continue

        # Certs to keep (newest N active) and certs to revoke (the rest)
        certs_to_keep = active_certs[:keep]
        certs_to_revoke = active_certs[keep:]

        ees_processed += 1
        n_to_revoke = len(certs_to_revoke)

        print(f"\n  EE Username:   {ee_name}")
        print(f"  Total certs:   {len(certs)} "
              f"({len(active_certs)} active, {already_revoked} already revoked)")
        if keep > 0:
            print(f"  Keeping:       {keep} newest active")
            for j, c in enumerate(certs_to_keep):
                s = _format_serial(c.get("serialNumber", ""))
                nb = _format_cert_time(c.get("notBefore"))
                print(f"    keep   {s}  ({nb})")
        else:
            print(f"  Keeping:       (none — revoking all)")
        print(f"  To revoke:     {n_to_revoke}")
        for j, c in enumerate(certs_to_revoke):
            s = _format_serial(c.get("serialNumber", ""))
            nb = _format_cert_time(c.get("notBefore"))
            print(f"    revoke {s}  ({nb})")
        sys.stdout.flush()

        total_kept += keep
        total_already_revoked += already_revoked

        if is_dry:
            total_revoked += n_to_revoke
            ees_with_revocations += 1
            continue

        # Execute revocations
        ee_revoked = 0
        for cert in certs_to_revoke:
            issuer_dn = cert.get("issuerDN", "")
            serial = cert.get("serialNumber", "")
            if not issuer_dn or not serial:
                log.warning(f"  Missing issuerDN or serial for cert, skipping")
                total_errors += 1
                continue
            if client.revoke_certificate(issuer_dn, serial,
                                         reason=args.revoke_reason):
                ee_revoked += 1
            else:
                total_errors += 1

        total_revoked += ee_revoked
        if ee_revoked > 0:
            ees_with_revocations += 1
        print(f"  Result:        {ee_revoked}/{n_to_revoke} revoked")
        if args.delete_ee and keep == 0:
            ees_to_delete.append(ee_name)

    # Summary
    print(f"\n{'=' * 78}")
    print(f"{'DRY RUN — ' if is_dry else ''}Cleanup Summary "
          f"(-keep-newest {keep})")
    print(f"{'=' * 78}")
    print(f"EEs scanned:     {len(ee_names)}")
    print(f"EEs with excess: {ees_processed}")
    print(f"Certs kept:      {total_kept}")
    print(f"Certs revoked:   {total_revoked}"
          f"{'  (would revoke)' if is_dry else ''}")
    print(f"Already revoked: {total_already_revoked}")
    if total_errors:
        print(f"Errors:          {total_errors}")
    if is_dry:
        print(f"\nTo execute, re-run with -commit")
    print(f"{chr(61) * 78}")
    print()

    # EE deletion pass (after cert revocations)
    if args.delete_ee and ees_to_delete:
        if is_dry:
            print(f"Would delete {len(ees_to_delete)} EE(s) (re-run with -commit):")
            for name in ees_to_delete:
                print(f"  delete EE:  {name}")
        else:
            noun = "y" if len(ees_to_delete) == 1 else "ies"
            print(f"Deleting {len(ees_to_delete)} End Entit{noun}...")
            deleted = 0
            for name in ees_to_delete:
                try:
                    client.delete_end_entity(name)
                    print(f"  deleted EE: {name}")
                    deleted += 1
                except Exception as e:
                    log.error(f"  Failed to delete EE {name!r}: {e}")
            print(f"EEs deleted:     {deleted}/{len(ees_to_delete)}")
        print()


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

class SmartHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Preserves explicit \\n in help text while wrapping long lines."""

    def _split_lines(self, text, width):
        lines = []
        for line in text.splitlines():
            lines.extend(super()._split_lines(line, width))
        return lines


class LifecycleArgumentParser(argparse.ArgumentParser):
    """ArgumentParser with custom error and usage formatting."""

    def format_usage(self):
        """Custom usage with version header."""
        return (f"\nejbca-lifecycle-tool.py v{__version__}\n\n"
                + self.usage % {"prog": self.prog} + "\n")

    def format_help(self):
        """Custom help suppressing argparse's default usage formatting."""
        formatter = self._get_formatter()
        # Add our usage directly
        formatter.add_text(self.format_usage())
        # Add argument groups
        for action_group in self._action_groups:
            formatter.start_section(action_group.title)
            formatter.add_arguments(action_group._group_actions)
            formatter.end_section()
        # Add epilog
        formatter.add_text(self.epilog)
        return formatter.format_help() + "\n"

    def error(self, message):
        sys.stderr.write(f"\nerror: {message}\n\n")
        env_tip = (
            "  tip: connection args can also be set via environment variables:\n"
            "    ELT_HOST, ELT_PORT, ELT_CERT, ELT_KEY, ELT_CA_CERT\n")
        if "required" in message.lower() or "unrecognized" in message.lower():
            sys.stderr.write(env_tip)
        sys.stderr.write(f"\nRun with -H for full help.\n\n")
        sys.exit(2)


def build_parser() -> argparse.ArgumentParser:

    usage = """Usage:  %(prog)s
    [-H | --help] [-V] [-v] [-F] [--hints]
    -ejbca-host HOST
    -client-cert FILE
    -client-key FILE
    [-ejbca-port PORT]
    [-ca-cert FILE]
    [-no-verify-ssl]
    [-no-proxy]
    [-f YAML]
    [-ee-profile NAME_OR_ID]
    [-ee-username NAME]
    [-active] [-revoked]
    [-cert-cn TEXT]
    [-cert-serial TEXT]
    [-max-end-entities N]
    [-max-certs N]
    [-k8s-compare]
    [-k8s-status STATUS]
    [-kubectl PATH]
    [-ghosts]
    [-d {1,2,3,4}]
    [-c0] [-c1] [-c2]
    [-commit] [-keep-newest N] [-all]
    [--delete-ee] [--delete-after-revoke]
    [-revoke-reason REASON]
    {list, count, ping, cleanup}

    shortcuts: list1 list2 list3 list4 = list -d1..d4
"""

    epilog = """
examples:
  # Connection via environment variables
  $ export ELT_HOST=ejbca.example.com               # --ejbca-host
  $ export ELT_PORT=8443                            # --ejbca-port
  $ export ELT_CERT=/path/to/client.crt             # --client-cert
  $ export ELT_KEY=/path/to/client.key              # --client-key
  $ export ELT_CA_CERT=/path/to/ca.pem              # --ca-cert
  $ export ELT_KUBECTL='/snap/bin/microk8s kubectl' # --kubectl
  $ export ELT_VERIFY_SSL=no                        # --no-verify-ssl
  $ export ELT_PROXY=no                             # --no-proxy


  # Set a Bash convenience alias
  $ alias elt='python3 ejbca-lifecycle-tool.py'

  # Ping EJBCA to verify REST API connectivity, after setting environment variables
  $ elt ping
  $ elt ping -no-proxy -no-verify-ssl

  # Show EJBCA configuration recommendations
  $ elt --hints

  # List EE profiles (level 1)
  $ elt list1
  $ elt list -d1

  # List profiles + cert profiles (level 2)
  $ elt list2
  $ elt list2 -ee-profile home_SG-ClientAuth-End-Entity

  # List EE usernames with cert counts (level 3)
  $ elt list3
  $ elt list3 -F
  $ elt list3 -ee-profile 385738093
  $ elt list3 -ee-profile orphans
  $ elt list3 -ee-username "k8s-cert-1234.pkirules"

  # List all certificates per EE (level 4)
  $ elt list4
  $ elt list4 -F
  $ elt list4 -ee-username "k8s renew hourly"
  $ elt list4 -ee-profile orphans -F
  $ elt list4 -k8s-compare
  $ elt list4 -k8s-status orphaned

  # Search for certificates by CN or serial number
  $ elt list4 -cert-cn "TEST Renewal Hourly"
  $ elt list4 -cert-serial "5f:b6:71:20"
  $ elt list4 -cert-serial "5fb67120"
  $ elt count -cert-cn "web-server"

  # Certificate count overview (sorted by count)
  $ elt count
  $ elt count -ee-profile "My-Profile"
  $ elt count -ee-username "k8s-cert-1234.pkirules"
  $ elt count -k8s-compare
  $ elt count -k8s-status orphaned

  # Verify EJBCA REST API behaviour (with -v, tests END_ENTITY_PROFILE criterion)
  $ elt ping -v

  # Ghost EE detection (cert records outliving deleted EE username)
  $ elt count -ghosts                             # summary: how many ghosts?
  $ elt list3 -ghosts                             # ghost usernames + cert counts
  $ elt list4 -ghosts                             # ghost usernames + full cert tables

  # Cross-reference with Kubernetes
  $ elt list3 -k8s-compare
  $ elt list3 -k8s-compare -F
  $ elt list3 -k8s-status orphaned
  $ elt list3 -k8s-status active

  # Cleanup EE-level (dry-run by default)
  $ elt cleanup -k8s-compare -ee-profile "My-Profile"
  $ elt cleanup -k8s-compare -ee-profile "My-Profile" -commit
  $ elt cleanup -ee-profile "My-Profile" --delete-ee -all -commit

  # Cleanup per-cert: revoke all but newest N certs per EE (keeps EE intact)
  $ elt cleanup -keep-newest 1 -ee-username "TEST Renewal Hourly"
  $ elt cleanup -keep-newest 1 -ee-profile "My-Profile" -all
  $ elt cleanup -keep-newest 2 -ee-profile "My-Profile" -all -commit

  # Revoke all certs and delete EE in one step:
  $ elt cleanup --delete-ee -ee-username "orphan-ee-name"
  $ elt cleanup --delete-ee -ee-username "orphan-ee-name" -commit

  # Or two explicit steps (revoke first, then delete):
  $ elt cleanup -keep-newest 0 -ee-username "orphan-ee-name" -commit
  $ elt cleanup --delete-ee -ee-username "orphan-ee-name" -commit

"""

    parser = LifecycleArgumentParser(
        prog="ejbca-lifecycle-tool.py",
        usage=usage,
        epilog=epilog,
        formatter_class=SmartHelpFormatter,
        add_help=False,
    )

    parser.add_argument("-H", "--help", action="help",
                        default=argparse.SUPPRESS,
                        help="Show this help message and exit")

    class _DeprecatedH(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            parser.exit(0,
                "  Use  -H / --help   for the help page\n"
                "  Use  --hints       for EJBCA configuration recommendations\n"
            )
    parser.add_argument("-h", nargs=0, action=_DeprecatedH,
                        default=argparse.SUPPRESS,
                        help=argparse.SUPPRESS)
    parser.add_argument("-V", "--version", action="version",
                        version=f"%(prog)s v{__version__}",
                        help="Show version and exit")
    parser.add_argument("--hints", action="store_true",
                        help="Show my EJBCA config recommendations for cert-manager")

    # --- Connection arguments ---
    conn = parser.add_argument_group("connection")
    conn.add_argument("-ca-cert",
                      default=os.environ.get("ELT_CA_CERT"),
                      metavar="FILE",
                      help="CA cert chain for SSL verification [env: ELT_CA_CERT]")
    conn.add_argument("-client-cert",
                      default=os.environ.get("ELT_CERT"),
                      metavar="FILE",
                      help="mTLS client certificate [env: ELT_CERT]")
    conn.add_argument("-client-key",
                      default=os.environ.get("ELT_KEY"),
                      metavar="FILE",
                      help="mTLS client key [env: ELT_KEY]")
    conn.add_argument("-ejbca-host", default=os.environ.get("ELT_HOST"),
                      metavar="HOST",
                      help="EJBCA hostname [env: ELT_HOST]")
    conn.add_argument("-ejbca-port", type=int,
                      default=int(os.environ.get("ELT_PORT", "443")),
                      metavar="PORT",
                      help="EJBCA port [env: ELT_PORT, default: 443]")
    conn.add_argument("-no-proxy", action="store_true",
                      default=os.environ.get("ELT_PROXY", "").lower() == "no",
                      help="Bypass proxy for direct mTLS [env: ELT_PROXY=no]")
    conn.add_argument("-no-verify-ssl", action="store_true",
                      default=os.environ.get("ELT_VERIFY_SSL", "").lower() == "no",
                      help="Disable SSL verification [env: ELT_VERIFY_SSL=no]")

    # --- Backend selection (v4.0.0) ---
    # EJBCA CE doesn't ship the End Entity REST API; targeting CE requires
    # the SOAP backend. EE works on either, defaulting to REST. Precedence:
    # explicit flag → ELT_BACKEND env var → auto-detect (probe a Management
    # REST endpoint; 404 → SOAP).
    backend_mutex = conn.add_mutually_exclusive_group()
    backend_mutex.add_argument("-z", "--zeep", action="store_true",
                               help="Force SOAP backend for End Entity ops. "
                                    "Use against EJBCA Community Edition. "
                                    "Requires 'zeep' [env: ELT_BACKEND=soap]")
    backend_mutex.add_argument("--rest", action="store_true",
                               help="Force REST backend (legacy default). "
                                    "Overrides auto-detection [env: ELT_BACKEND=rest]")

    # --- Filter arguments ---
    filt = parser.add_argument_group("filtering")
    filt.add_argument("-active", dest="active_only", action="store_true",
                      help="Show only EEs with active certs (list); also "
                           "filters the cert table in list -d4 to active "
                           "rows only.  Active = not revoked, not expired.")
    filt.add_argument("-cert-cn", default=None, metavar="TEXT",
                      help="Filter certificates by CN substring match (implies -F)")
    filt.add_argument("-cert-serial", default=None, metavar="TEXT",
                      help="Filter certs by serial substring (with or without colons; implies -F)")
    filt.add_argument("-c0", action="store_const", const=0,
                      dest="cert_detail", default=0,
                      help="Compact cert table (default in -d4)")
    filt.add_argument("-c1", action="store_const", const=1,
                      dest="cert_detail",
                      help="Certificate block with CN (in -d4)")
    filt.add_argument("-c2", action="store_const", const=2,
                      dest="cert_detail",
                      help="Certificate block with full DN (in -d4)")
    filt.add_argument("-d", type=int, default=3,
                      dest="detail",
                      choices=[1, 2, 3, 4], metavar="{1,2,3,4}",
                      help="Detail level for list command (default: -d3)")
    filt.add_argument("-ee-profile", default=None, metavar="NAME_OR_ID",
                      help="EE Profile name, ID, or 'orphans' (default: all)")
    filt.add_argument("-ee-username", default=None, metavar="NAME",
                      help="Specific EE username (for single-EE drill-down)")
    filt.add_argument("-f", dest="file", default=None, metavar="YAML",
                      help="Read EE profile from cert-manager Issuer YAML")
    filt.add_argument("-F", action="store_true",
                      dest="show_full",
                      help="Show full output (default: first 3 items)")
    filt.add_argument("-ghosts", action="store_true",
                      help="Detect ghost EE usernames: cert records that "
                           "outlived their deleted EE. "
                           "Applies to list -d3/d4 and count.")
    filt.add_argument("-k8s-compare", action="store_true",
                      help="Cross-reference with cert-manager (requires kubectl)")
    filt.add_argument("-k8s-status", default=None, metavar="STATUS",
                      help="Filter by K8s status: 'active' or 'orphaned' "
                           "(implies -k8s-compare)")
    filt.add_argument("-kubectl", default=os.environ.get("ELT_KUBECTL", "kubectl"),
                      metavar="PATH",
                      help="Path to kubectl binary or command "
                           "(default: kubectl, or ELT_KUBECTL env var).\n"
                           "Example: -kubectl '/snap/bin/microk8s kubectl'")
    filt.add_argument("-max-certs", type=int, default=10000,
                      dest="max_certs",
                      help="Max certificates per EE query (default: 10000)")
    filt.add_argument("-max-end-entities", type=int, default=500,
                      dest="max_end_entities",
                      help="Max End Entities per status query (default: 500)")
    filt.add_argument("-revoked", dest="revoked_only", action="store_true",
                      help="Show only EEs with revoked certs (list); also "
                           "filters the cert table in list -d4 to revoked "
                           "rows only.")
    filt.add_argument("-sort", dest="sort_field", default=None,
                      choices=["total", "active", "expired", "revoked"],
                      metavar="FIELD",
                      help="count: primary sort field — total|active|expired"
                           "|revoked (default: active)")
    filt.add_argument("-status-filter", default=None,
                      dest="status_filter",
                      help="(expert) Raw EJBCA EE status filter "
                           "(NEW, GENERATED, REVOKED, ...)")

    # --- Output arguments ---
    parser.add_argument("-v", action="count", default=0,
                        dest="verbose",
                        help="Increase verbosity (-v info, -vv debug)")
    parser.add_argument("--dump-json", action="store_true",
                        help=argparse.SUPPRESS)

    # --- Cleanup arguments (on main parser for subcommand-anywhere compat) ---
    cleanup = parser.add_argument_group("cleanup options")
    cleanup.add_argument("-all", dest="all_matching",
                         action="store_true",
                         help="Operate on ALL matching EEs "
                              "(required without -k8s-compare)")
    cleanup.add_argument("-commit", "-confirm", action="store_true",
                         help="Actually execute changes")
    cleanup.add_argument("--delete-after-revoke", action="store_true",
                         help="Delete EE after revoking certs")
    cleanup.add_argument("--delete-ee", "--delete-only",
                         dest="delete_ee", action="store_true",
                         help="Delete the End Entity (without revoking certs).\n"
                              "Alias: --delete-only (same action, different perspective)")
    cleanup.add_argument("--dry-run", action="store_true", default=True,
                         help="Show what would be done (default)")
    cleanup.add_argument("-keep-newest", type=int, default=None,
                         metavar="N",
                         help="Per-cert cleanup: revoke all but newest N.\n"
                              "N=0 revokes all; keeps EE intact.")
    cleanup.add_argument("-revoke-reason", default="SUPERSEDED",
                         dest="revoke_reason",
                         help="CRL reason (default: SUPERSEDED)")

    # --- Subcommands ---
    subparsers = parser.add_subparsers(dest="command", title="actions")

    subparsers.add_parser("list",
                          help="List EE profiles, entities, and certificates "
                               "(use -d1..d4 for detail level)")

    subparsers.add_parser("count",
                          help="Certificate count overview: global totals "
                               "and per-EE breakdown table")

    subparsers.add_parser("ping",
                          help="Verify REST API connectivity")

    subparsers.add_parser("cleanup",
                          help="Revoke/delete EEs or per-cert "
                               "cleanup (dry-run by default)")

    return parser


# ---------------------------------------------------------------------------
# Hints: EJBCA configuration recommendations
# ---------------------------------------------------------------------------

def _print_hints():
    """Print EJBCA configuration recommendations for cert-manager."""
    print(f"""
ejbca-lifecycle-tool.py v{__version__} — Configuration Hints

Here are my EJBCA configuration recommendations for optimal K8s cert-manager
lifecycle management. These settings minimize certificate accumulation,
enable automated cleanup, and align with industry best practices.
Tested with EJBCA Enterprise / Software Appliance, versions 9.3.3 - 9.4.2.

Tip: To see the associations of EE Profile, Cert Profile, and CA:
  $ ejbca-lifecycle-tool.py list2

CA Configuration
  - only for the "Issuing CA" referenced by the End Entity Profile.
  Enforce unique public keys: unchecked (avoid obscure errors and DB indexes)
  Enforce unique DN:          unchecked (same CN reused across renewals)
  Finish User:                checked (password not blanked for User Generated tokens)

Certificate Profile
  - only for the "Leaf certificate profile" referenced by the End Entity Profile.
  Type:                       End Entity
  Validity:                   47 days (short-lived, auto-renewed by cert-manager)
  Allow Validity Override:    checked (needed once the cert-manager issuer
                                supports passing requested validity to EJBCA)
  Single Active Cert:         checked (auto-revokes previous cert on renewal)

End Entity Profile
  - only for the "End Entity profiles" used by K8s cert-manager enrollments
  Username:                   Auto-generated: checked
                                (EJBCA assigns unique username; cert-manager
                                issuer may override via endEntityName)
  Password:                   Required: unchecked, Auto-generated: unchecked
                                (avoid credential mismatches between admins)
  Batch generation:           checked (allows automated re-enrollment for renewals,
                                avoiding "No password in request" error 400)
  Number of allowed requests: leave "Use" unchecked (unlimited re-enrollment)
  Default Token:              User Generated (cert-manager generates keys)
  Available Tokens:           all can be selected (supports RA Web exports)

  Note on "Allow Renewal Before Expiration": leave it unchecked.
  - This EJBCA feature allows re-enrollment while the EE is in GENERATED status.
  - But cert-manager does NOT use this mechanism.
  - The PKCS10 Enroll endpoint resets the EE to NEW status on each request,
    so it bypasses the GENERATED-status check entirely.
  - cert-manager "renewal" is really a fresh enrollment that reuses the EE username:
    new key, new serial, new CSR.

Role & Access Rules
  Role template:              RA Administrators
  Additional rules:           /system_functionality/view_systemconfiguration/
                                (needed for 'elt count' global totals)
  REST protocol:              REST Certificate Management must be enabled
  Authorized CAs:             select relevant CAs
  Authorized EE Profiles:     select relevant profiles
  Trusted CA list:            add the CA of your access certificate

Database Maintenance Service (Enterprise)
  Name:                       DBMS Certificate Reaper
  CAs to Check:               all CAs
  Delay After Expiration:     minimum allowed (DEV: 1 day, PROD: per compliance)
  Delete Expired Certs:       true
  Delete Expired CRLs:        true
  Entries per run:            1000-5000 (increase for large backlogs)
  Description:                Purge expired/revoked cert records and old CRLs

Why 47-Day Certificates?
  - CA/B Forum and Apple/Google converging on short TLS lifetimes
  - cert-manager handles renewals automatically (invisible to apps)
  - Revoked/expired certs purged by Database Maintenance in weeks, not years
  - Accumulation bounded: ~47 active certs max per EE (vs ~1095 for 3-year)
  - Reduced blast radius: compromised cert valid for weeks, not years

Known Gotchas
  - cert-manager "duration" field is ignored by EJBCA — cert lifetime
    is always set by the Certificate Profile validity, not the K8s YAML.
    Set renewBefore relative to the actual EJBCA-issued validity.
    ( https://github.com/Keyfactor/ejbca-cert-manager-issuer/issues/128 )

  - Single Active Cert may produce a duplicate cert (same NotBefore) on
    first renewal after config change — likely a one-time race condition

  - EE usernames are globally unique — collision risk in multi-tenant
    (consider deterministic hash for endEntityName)

  - Revoked certs with long remaining validity: ghost records persist
    until original expiry + delay (reason to use short-lived certs)

  - Always revoke before deleting EE (else: active ghost cert, no CRL entry)

  - EE-level revoke API may return 500 for EJBCA-generated keys
    (workaround: per-cert revoke via 'elt cleanup -keep-newest 0')
""")


# ---------------------------------------------------------------------------
# Backend resolution — Phase 5.5
# ---------------------------------------------------------------------------
#
# Picks between the REST methods on EjbcaClient (default) and the SOAP
# EjbcaSoapBackend, then attaches the backend to the client. Precedence:
#   1. CLI flag (-z/--zeep or --rest) — explicit user override
#   2. Env var (ELT_BACKEND=rest|soap|zeep|auto)
#   3. Auto-detect — probe a Management REST endpoint; 404 → SOAP
#
# The default state of EjbcaClient._ee_backend is None (REST). When this
# function decides SOAP is needed, it constructs an EjbcaSoapBackend with
# the same connection params and attaches it to the client. 5.3's dispatch
# (added below at each EE method) then routes End Entity calls to SOAP.

def _auto_detect_backend(client) -> str:
    """Probe a Management REST endpoint to decide REST vs SOAP.

    Returns 'rest' on HTTP 200, 'soap' on 404 (the CE signature), or
    'rest' for anything else (conservative default).
    """
    probe = "/v2/endentity/profiles/authorized/"
    log.debug(f"Backend auto-detect: GET {probe}")
    resp = client._request("GET", probe, log_errors=False)
    if resp.status_code == 200:
        log.info("Auto-detect: Management REST returned 200 → REST backend "
                 "(EJBCA EE detected)")
        return "rest"
    if resp.status_code == 404:
        log.info("Auto-detect: Management REST returned 404 → SOAP backend "
                 "(EJBCA CE detected)")
        return "soap"
    log.warning(f"Auto-detect: Management REST probe returned "
                f"{resp.status_code}; defaulting to REST")
    return "rest"


def _resolve_backend_choice(args, client) -> str:
    """Return 'rest' or 'soap' per the precedence chain above."""
    # 1) Explicit CLI flag
    if getattr(args, "rest", False):
        log.debug("Backend selection: --rest flag → REST")
        return "rest"
    if getattr(args, "zeep", False):
        log.debug("Backend selection: --zeep flag → SOAP")
        return "soap"

    # 2) Environment variable
    env = os.environ.get("ELT_BACKEND", "").strip().lower()
    if env == "rest":
        log.debug("Backend selection: ELT_BACKEND=rest → REST")
        return "rest"
    if env in ("soap", "zeep"):
        log.debug(f"Backend selection: ELT_BACKEND={env} → SOAP")
        return "soap"
    if env and env != "auto":
        log.warning(f"Unknown ELT_BACKEND={env!r}; falling back to auto-detect")

    # 3) Auto-detect
    return _auto_detect_backend(client)


def _attach_ee_backend(args, client) -> None:
    """Resolve backend choice; if SOAP, construct and attach to client."""
    choice = _resolve_backend_choice(args, client)
    if choice != "soap":
        return  # REST is the default; client._ee_backend stays None
    client._ee_backend = EjbcaSoapBackend(
        host=args.ejbca_host,
        port=args.ejbca_port,
        client_cert=args.client_cert,
        client_key=getattr(args, "client_key", None),
        ca_cert=args.ca_cert,
        verify_ssl=not args.no_verify_ssl,
        no_proxy=args.no_proxy,
    )
    log.info(f"ELT v{__version__}: SOAP backend active for End Entity operations")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Force line-buffered stdout so output appears immediately,
    # even when piped through tee or redirected to a file.
    sys.stdout.reconfigure(line_buffering=True)

    _shortcuts = {
        "list1": {"cmd": "list", "inject": ["-d", "1"]},
        "list2": {"cmd": "list", "inject": ["-d", "2"]},
        "list3": {"cmd": "list", "inject": ["-d", "3"]},
        "list4": {"cmd": "list", "inject": ["-d", "4"]},
    }
    _subcommands = {"ping", "list", "count", "cleanup"}

    argv = sys.argv[1:]

    # Expand shortcuts first
    for i, arg in enumerate(argv):
        if arg in _shortcuts:
            sc = _shortcuts[arg]
            before = argv[:i]
            after = argv[i+1:]
            argv = before + sc["inject"] + after + [sc["cmd"]]
            break

    # Move subcommand to end so flags before it go to the main parser
    for i, arg in enumerate(argv):
        if arg in _subcommands:
            argv = argv[:i] + argv[i+1:] + [arg]
            break

    parser = build_parser()
    args = parser.parse_args(argv)

    # Validate env vars that only accept "no"
    for env_name, env_label in [("ELT_VERIFY_SSL", "-no-verify-ssl"),
                                ("ELT_PROXY", "-no-proxy")]:
        val = os.environ.get(env_name, "")
        if val and val.lower() != "no":
            log.error(f"Invalid {env_name}='{val}' — only 'no' is supported "
                      f"(sets {env_label})")
            sys.exit(1)

    # --hints: print recommendations and exit (no connection needed)
    if args.hints:
        _print_hints()
        return

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Set verbosity early
    if args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose >= 1:
        logging.getLogger().setLevel(logging.INFO)

    log.info(f"ejbca-lifecycle-tool v{__version__}")

    # cert_detail: 0=compact table, 1=block+CN, 2=block+full DN
    # (replaces old cert_info / cert_info_full booleans)

    # --k8s-status implies --k8s-compare and validate value
    if args.k8s_status:
        val = args.k8s_status.lower()
        if val in ("active", "orphan", "orphaned"):
            args.k8s_status = "orphaned" if val.startswith("orphan") else "active"
            args.k8s_compare = True
        else:
            log.error(f"Invalid -k8s-status value: '{args.k8s_status}'"
                      f"\n    Allowed values: 'active' or 'orphaned'")
            sys.exit(1)

    # Ping doesn't need full connection validation
    if args.command == "ping":
        missing = []
        if not args.ejbca_host:
            missing.append("-ejbca-host (or ELT_HOST)")
        if not args.client_cert:
            missing.append("-client-cert (or ELT_CERT)")
        if missing:
            log.error("Missing required connection arguments:\n"
                      + "".join(f"    {m}\n" for m in missing))
            sys.exit(1)
        client = EjbcaClient(
            host=args.ejbca_host,
            port=args.ejbca_port,
            client_cert=args.client_cert,
            client_key=getattr(args, "client_key", None),
            ca_cert=args.ca_cert,
            verify_ssl=not args.no_verify_ssl,
            no_proxy=args.no_proxy,
        )
        _attach_ee_backend(args, client)
        print(f"ejbca-lifecycle-tool.py v{__version__}")
        cmd_ping(args, client)
        return

    # All other commands need full connection
    missing = []
    if not args.ejbca_host:
        missing.append("-ejbca-host (or ELT_HOST)")
    if not args.client_cert:
        missing.append("-client-cert (or ELT_CERT)")
    if missing:
        log.error(
            "Missing required connection arguments:\n"
            + "".join(f"    {m}\n" for m in missing)
            + "\n"
            "  tip: connection args can also be set via environment variables:\n"
            "    ELT_HOST, ELT_PORT, ELT_CERT, ELT_KEY, ELT_CA_CERT\n")
        sys.exit(1)

    client = EjbcaClient(
        host=args.ejbca_host,
        port=args.ejbca_port,
        client_cert=args.client_cert,
        client_key=getattr(args, "client_key", None),
        ca_cert=args.ca_cert,
        verify_ssl=not args.no_verify_ssl,
        no_proxy=args.no_proxy,
    )
    _attach_ee_backend(args, client)

    # Verify connectivity
    log.info(f"Connecting to EJBCA at {args.ejbca_host}:{args.ejbca_port}")
    if client._ee_backend is None:
        # REST mode — probe the v2 status endpoint to log API version info.
        # In SOAP mode the endpoint isn't shipped in CE (would 404 noisily);
        # _attach_ee_backend's auto-detect already confirmed reachability.
        status = client.get_end_entity_status()
        if status:
            log.info(f"EJBCA End Entity API status: {status.get('status', '?')}")

    print(f"ejbca-lifecycle-tool.py v{__version__}")

    if args.command == "list":
        cmd_list(args, client)
    elif args.command == "count":
        cmd_count(args, client)
    elif args.command == "cleanup":
        cmd_cleanup(args, client)
    elif args.command == "ping":
        cmd_ping(args, client)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
