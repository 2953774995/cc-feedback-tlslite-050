# Authors:
#   tlslite-ng contributors
#
# See the LICENSE file for legal information regarding use of this file.

"""Offline audit of TLS endpoint configuration.

Static, IANA-name based classification of cipher suites and protocol
versions.  Nothing in this module performs a handshake or any network I/O
and no third party dependencies are used; the only data source is the
cipher suite constant table in :mod:`tlslite.constants`.

The two public entry points are:

* :func:`audit_cipher_suites` - weak algorithm / forward secrecy / unknown
  name / duplicate classification for a list of IANA cipher suite names
* :func:`audit_versions` - protocol minimum version enforcement for a list
  of version labels such as ``"TLSv1_2"``
"""

import re

from .constants import CipherSuite


class AuditResult(object):
    """Container for an audit run.

    :vartype items: list of dict
    :ivar items: one dictionary per entry of the input, in input order;
        every dictionary carries at least ``index`` (1-based), ``name``,
        ``ok``, ``reason`` and ``issues``.
    :vartype stats: dict
    :ivar stats: aggregate counters with ``ok``, ``bad`` and ``by_reason``.
    """

    def __init__(self, items=None, stats=None):
        self.items = items if items is not None else []
        self.stats = stats if stats is not None else \
            {"ok": 0, "bad": 0, "by_reason": {}}


# Reverse lookup: IANA name -> numeric suite id, built once from the
# constant table so the audit never hard-codes individual suite numbers.
_NAME_TO_ID = dict(
    (name, code) for code, name in CipherSuite.ietfNames.items())


# Stable issue codes reported verbatim in the per-item ``issues`` lists;
# the code itself names the matched weakness so the list can be pasted
# straight into a remediation ticket.
ISSUE_RC4 = "rc4"
ISSUE_3DES = "3des"
ISSUE_DES = "des"
ISSUE_NULL = "null"
ISSUE_EXPORT = "export"
ISSUE_ANON = "anonymous"
ISSUE_NO_FORWARD_SECRECY = "no_forward_secrecy"

# Order in which weak-cipher issues are reported when more than one matches
# (e.g. an anonymous EXPORT RC4 suite hits three rules).
_WEAK_ORDER = (ISSUE_RC4, ISSUE_3DES, ISSUE_DES, ISSUE_NULL,
               ISSUE_EXPORT, ISSUE_ANON)

# Symmetric key strength (bits) per cipher family.  For EXPORT suites the
# effective, restricted strength is used rather than the nominal key size.
_BITS_RULES = (
    ("EXPORT40", 40),
    ("AES_256", 256),
    ("AES_128", 128),
    ("CHACHA20", 256),
    ("3DES_EDE", 112),
    ("DES_64", 56),
    ("RC4_128", 128),
    ("IDEA_128", 128),
    ("NULL", 0),
)

# Key exchange prefixes (first IANA name token) that negotiate ephemeral
# Diffie-Hellman parameters and therefore provide forward secrecy.
_FORWARD_SECRET_EXCHANGES = frozenset(("DHE", "ECDHE"))

# Regex extracting the key exchange token: the first token after the
# ``TLS_`` prefix, e.g. ECDHE in ``TLS_ECDHE_RSA_WITH_...``.
_EXCHANGE_RE = re.compile(r"^TLS_([A-Za-z0-9]+)_")


def _weak_issues(name):
    """Return the weak-algorithm issue codes matched by ``name``."""
    issues = []
    if "RC4" in name:
        issues.append(ISSUE_RC4)
    if "3DES" in name or "EDE3" in name:
        issues.append(ISSUE_3DES)
    # Single DES: only the SSLv2 ``SSL_CK_DES_...`` names; the 3DES
    # variants carry ``3DES``/``EDE3`` and are handled above.
    if name.startswith("SSL_CK_") and "DES" in name \
            and "3DES" not in name and "EDE3" not in name:
        issues.append(ISSUE_DES)
    if "NULL" in name:
        issues.append(ISSUE_NULL)
    if "EXPORT" in name:
        issues.append(ISSUE_EXPORT)
    if "ANON" in name:
        issues.append(ISSUE_ANON)
    # Keep a stable, documented order regardless of substring hit order.
    return [code for code in _WEAK_ORDER if code in issues]


def _symmetric_bits(name):
    """Return the symmetric key strength in bits for ``name``."""
    for marker, bits in _BITS_RULES:
        if marker in name:
            return bits
    return None


def _has_forward_secrecy(name):
    """Return True when the suite's key exchange is ECDHE/DHE based."""
    # TLS 1.3 suites (``TLS_AES_...`` / ``TLS_CHACHA20_...``) always use an
    # ephemeral (D)TLS key exchange, but they do not carry a WITH token.
    if name.startswith("TLS_") and "_WITH_" not in name:
        if name in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_AES_128_CCM_SHA256",
                    "TLS_AES_128_CCM_8_SHA256"):
            return True
        # SCSV sentinels are not negotiable cipher suites.
        return False
    match = _EXCHANGE_RE.match(name)
    if match is None:
        return False
    return match.group(1).upper() in _FORWARD_SECRET_EXCHANGES


def audit_cipher_suites(names, require_forward_secrecy=True):
    """Audit a list of IANA cipher suite names.

    Each name is classified as ``ok``, ``weak_cipher``, ``unknown`` or
    ``duplicate``.  Weak suites are those using RC4, 3DES, single DES,
    NULL encryption, EXPORT-grade crypto or anonymous (aNULL) key exchange.
    Suites without an ECDHE/DHE key exchange lack forward secrecy; this is
    reported through the ``no_forward_secrecy`` issue without changing the
    item's reason, so a compliant but non-PFS suite stays ``ok`` with a
    non-empty ``issues`` list.

    :type names: list of str
    :param names: IANA cipher suite names, e.g.
        ``"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"``.
    :type require_forward_secrecy: bool
    :param require_forward_secrecy: when True (default) non-PFS suites get
        the ``no_forward_secrecy`` issue.
    :rtype: AuditResult
    :return: per-item findings plus aggregate statistics.
    """
    items = []
    by_reason = {}
    first_seen = {}
    ok_count = 0

    for index, name in enumerate(names, start=1):
        item = {
            "index": index,
            "name": name,
            "ok": False,
            "reason": None,
            "bits": None,
            "forward_secrecy": False,
            "issues": [],
        }

        if name in first_seen:
            item["reason"] = "duplicate"
            # 0-based position of the first occurrence (probe contract).
            item["duplicate_of"] = first_seen[name]
        elif name not in _NAME_TO_ID:
            item["reason"] = "unknown"
            first_seen[name] = index - 1
        else:
            first_seen[name] = index - 1
            weak = _weak_issues(name)
            item["bits"] = _symmetric_bits(name)
            item["forward_secrecy"] = _has_forward_secrecy(name)

            issues = list(weak)
            if require_forward_secrecy and not item["forward_secrecy"]:
                issues.append(ISSUE_NO_FORWARD_SECRECY)
            item["issues"] = issues

            if weak:
                item["reason"] = "weak_cipher"
            else:
                item["reason"] = "ok"
                item["ok"] = True
                ok_count += 1

        if item["reason"] != "ok":
            by_reason[item["reason"]] = by_reason.get(item["reason"], 0) + 1
        items.append(item)

    stats = {
        "ok": ok_count,
        "bad": len(items) - ok_count,
        "by_reason": by_reason,
    }
    return AuditResult(items, stats)


# Ranked protocol versions: higher tuple means newer protocol.
_VERSION_ORDER = {
    "SSLv2": (2, 0),
    "SSLv3": (3, 0),
    "TLSv1_0": (3, 1),
    "TLSv1_1": (3, 2),
    "TLSv1_2": (3, 3),
    "TLSv1_3": (3, 4),
}


def audit_versions(versions, min_version="TLSv1_2"):
    """Audit a list of protocol version labels against a minimum version.

    Versions below ``min_version`` are reported with reason
    ``weak_version`` and ``ok=False``; labels absent from the known version
    table are ``unknown`` and a repeated label is ``duplicate`` with a
    ``duplicate_of`` pointer (0-based position) to its first occurrence.

    :type versions: list of str
    :param versions: version labels, e.g. ``"TLSv1_0"`` or ``"SSLv3"``.
    :type min_version: str
    :param min_version: lowest acceptable version label (default
        ``"TLSv1_2"``).
    :rtype: AuditResult
    :return: per-item findings plus aggregate statistics.
    """
    if min_version not in _VERSION_ORDER:
        raise ValueError("unknown min_version: {0!r}".format(min_version))
    floor = _VERSION_ORDER[min_version]

    items = []
    by_reason = {}
    first_seen = {}
    ok_count = 0

    for index, version in enumerate(versions, start=1):
        item = {
            "index": index,
            "name": version,
            "ok": False,
            "reason": None,
            "bits": None,
            "forward_secrecy": None,
            "issues": [],
        }

        if version in first_seen:
            item["reason"] = "duplicate"
            item["duplicate_of"] = first_seen[version]
        elif version not in _VERSION_ORDER:
            item["reason"] = "unknown"
            first_seen[version] = index - 1
        else:
            first_seen[version] = index - 1
            if _VERSION_ORDER[version] < floor:
                item["reason"] = "weak_version"
                item["issues"] = ["weak_version"]
            else:
                item["reason"] = "ok"
                item["ok"] = True
                ok_count += 1

        if item["reason"] != "ok":
            by_reason[item["reason"]] = by_reason.get(item["reason"], 0) + 1
        items.append(item)

    stats = {
        "ok": ok_count,
        "bad": len(items) - ok_count,
        "by_reason": by_reason,
    }
    return AuditResult(items, stats)
