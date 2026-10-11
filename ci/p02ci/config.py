"""Trusted configuration (A-4): package root, non-infrastructure allow-list, protected tooling paths, gate mode.

The file lives in ci/p02ci/ of the trusted base checkout, so it is covered by the adapter digest and by
code-owner review; the PR checkout's copy is never read. Standard library only.

Gate mode (A-3, D-CI-02): the reviewer environment is used only when the configuration carries a complete,
current attestation that `p02-risk-acknowledgement` exists with required reviewers, prevent-self-review, no
administrator bypass, a reviewer team that excludes PR authors and no secrets. Otherwise the documented
fail-on-risk fallback D-CI-02(b) applies: the review job fails whenever acknowledgement would be required.
"""
import datetime
import json
import re
from dataclasses import dataclass, field
from typing import Optional, Tuple


class ConfigError(Exception):
    pass


MANDATORY_PROTECTED = (".github/**", "ci/**", "src/**", "schema/**", "narrate/**", "CODEOWNERS", "docs/CODEOWNERS")
NON_INFRA_EXTENSIONS = frozenset(("md", "txt", "rst", "adoc", "png", "jpg", "jpeg", "gif", "svg"))
ENVIRONMENT_NAME = "p02-risk-acknowledgement"
ATTESTATION_BOOLS = ("required_reviewers", "prevent_self_review", "admin_bypass_disabled",
                     "reviewer_team_excludes_pr_authors", "no_environment_secrets")
ATTESTATION_KEYS = frozenset(ATTESTATION_BOOLS + ("environment", "method", "verified_by", "verified_on"))
ATTESTATION_METHODS = ("admin-api-read", "canary-pr")
MAX_ATTESTATION_AGE = 180
TOP_KEYS = frozenset(("config_version", "package_root", "max_packages", "max_walk_entries",
                      "non_infrastructure_allow_list", "protected_tooling", "gate", "comment"))
GATE_KEYS = frozenset(("mode", "attestation_max_age_days", "environment_attestation"))

_SEG_RE = re.compile(r"\A(?:\*\*|[A-Za-z0-9._+@=*-]+)\Z")
_LITERAL_SEG_RE = re.compile(r"\A[A-Za-z0-9._+@=-]+\Z")
_TEXT_RE = re.compile(r"\A[A-Za-z0-9 ._@-]{1,64}\Z")


@dataclass(frozen=True)
class Config:
    package_root: str
    max_packages: int
    max_walk_entries: int
    allow_list: Tuple[str, ...]
    protected: Tuple[str, ...]
    gate_mode: str
    attestation_max_age_days: int
    attestation: Optional[dict] = field(default=None)


# ----------------------------------------------------------------------------- glob
def _check_pattern(p) -> list:
    if not isinstance(p, str) or not p or len(p) > 200 or p.startswith("/"):
        raise ConfigError("pattern")
    segs = p.split("/")
    for s in segs:
        if s in ("", ".", "..") or not _SEG_RE.match(s) or ("**" in s and s != "**"):
            raise ConfigError("pattern segment")
    return segs


def _seg_regex(seg: str):
    return re.compile(r"\A" + "".join("[^/]*" if c == "*" else re.escape(c) for c in seg) + r"\Z")


def _seg_match(pseg: str, seg: str) -> bool:
    if "*" in pseg and seg.startswith(".") and not pseg.startswith("."):
        return False  # a wildcard never matches a dot-name (shell semantics)
    return bool(_seg_regex(pseg).match(seg))


def glob_match(pattern: str, path: str) -> bool:
    """`*` matches within one segment (never a leading dot); `**` matches zero or more segments in the middle
    of a pattern and one or more segments at its end. No other metacharacters."""
    psegs = pattern.split("/")
    segs = path.split("/")

    def rec(i, j):
        if i == len(psegs):
            return j == len(segs)
        p = psegs[i]
        if p == "**":
            if i == len(psegs) - 1:
                return j < len(segs)
            return any(rec(i + 1, k) for k in range(j, len(segs) + 1))
        return j < len(segs) and _seg_match(p, segs[j]) and rec(i + 1, j + 1)
    return rec(0, 0)


def _check_allow_pattern(p: str) -> None:
    segs = _check_pattern(p)
    last = segs[-1]
    if last == "**":
        raise ConfigError("allow-list pattern must be extension-qualified")
    if "." not in last:
        raise ConfigError("allow-list pattern must be extension-qualified")
    stem, ext = last.rsplit(".", 1)
    if ext.lower() not in NON_INFRA_EXTENSIONS or not _LITERAL_SEG_RE.match(ext) or not stem:
        raise ConfigError("allow-list extension not permitted")
    if "*" in ext:
        raise ConfigError("allow-list extension must be literal")


# ----------------------------------------------------------------------------- loading
def _no_dups(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ConfigError("duplicate key")
        obj[k] = v
    return obj


def _no_constant(_name):
    raise ConfigError("non-finite constant")


def _int(v, lo, hi, what):
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ConfigError(what)
    return v


def parse_config(data) -> Config:
    if not isinstance(data, dict) or set(data) - TOP_KEYS:
        raise ConfigError("top-level keys")
    if data.get("config_version") != "1":
        raise ConfigError("config_version")
    root = data.get("package_root")
    if not isinstance(root, str) or not root:
        raise ConfigError("package_root")
    for s in root.split("/"):
        if s in ("", ".", "..") or not _LITERAL_SEG_RE.match(s):
            raise ConfigError("package_root")
    max_packages = _int(data.get("max_packages"), 1, 10, "max_packages")
    max_walk = _int(data.get("max_walk_entries"), 1, 20000, "max_walk_entries")
    allow = data.get("non_infrastructure_allow_list")
    prot = data.get("protected_tooling")
    if not isinstance(allow, list) or not isinstance(prot, list) or len(allow) > 50 or len(prot) > 50:
        raise ConfigError("lists")
    for p in allow:
        _check_allow_pattern(p)
    for p in prot:
        _check_pattern(p)
    if set(MANDATORY_PROTECTED) - set(prot):
        raise ConfigError("mandatory protected path missing")
    if any(glob_match(p, root) or glob_match(p, root + "/x") for p in prot):
        raise ConfigError("package_root inside protected tooling")
    gate = data.get("gate")
    if not isinstance(gate, dict) or set(gate) - GATE_KEYS:
        raise ConfigError("gate")
    mode = gate.get("mode")
    if mode not in ("fail-on-risk", "environment"):
        raise ConfigError("gate mode")
    max_age = _int(gate.get("attestation_max_age_days"), 1, MAX_ATTESTATION_AGE, "attestation_max_age_days")
    att = gate.get("environment_attestation")
    if att is not None:
        if not isinstance(att, dict) or set(att) - ATTESTATION_KEYS:
            raise ConfigError("attestation keys")
        for k in ("environment", "method", "verified_by", "verified_on"):
            if k in att and (not isinstance(att[k], str) or not _TEXT_RE.match(att[k])):
                raise ConfigError("attestation text")
        att = dict(att)
    return Config(package_root=root, max_packages=max_packages, max_walk_entries=max_walk,
                  allow_list=tuple(allow), protected=tuple(prot), gate_mode=mode,
                  attestation_max_age_days=max_age, attestation=att)


def load_config(path: str) -> Config:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(65537)
        if len(raw) > 65536:
            raise ConfigError("config too large")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dups, parse_constant=_no_constant)
    except ConfigError:
        raise
    except (OSError, ValueError, UnicodeDecodeError):
        raise ConfigError("unreadable") from None
    return parse_config(data)


def effective_gate(cfg: Config, today: datetime.date):
    """Return (mode, note_code). 'environment' only for a complete, current attestation; else 'fail-on-risk'."""
    if cfg.gate_mode == "fail-on-risk":
        return "fail-on-risk", "GATE_FALLBACK_CONFIGURED"
    att = cfg.attestation
    if not att:
        return "fail-on-risk", "GATE_ATTESTATION_MISSING"
    if any(att.get(k) is not True for k in ATTESTATION_BOOLS):
        return "fail-on-risk", "GATE_ATTESTATION_INCOMPLETE"
    if att.get("environment") != ENVIRONMENT_NAME or att.get("method") not in ATTESTATION_METHODS \
            or not att.get("verified_by"):
        return "fail-on-risk", "GATE_ATTESTATION_INCOMPLETE"
    try:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", str(att.get("verified_on", ""))):
            raise ValueError  # R4 V4-08: calendar date YYYY-MM-DD only (no ISO week or ordinal forms)
        day = datetime.date.fromisoformat(att["verified_on"])
    except (ValueError, TypeError):
        return "fail-on-risk", "GATE_ATTESTATION_DATE_INVALID"
    if day > today:
        return "fail-on-risk", "GATE_ATTESTATION_DATE_INVALID"
    if (today - day).days > cfg.attestation_max_age_days:
        return "fail-on-risk", "GATE_ATTESTATION_EXPIRED"
    return "environment", None
