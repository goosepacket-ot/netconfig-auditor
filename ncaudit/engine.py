"""Rule engine for auditing network device configurations against a YAML hardening baseline.

A rule pack is YAML. Each rule has an id, a title, a severity and one check type:

  present      : a regex that MUST appear somewhere in the config
  absent       : a regex that must NOT appear (presence = a finding)
  present_all  : every regex in a list must appear
  absent_all   : none of the regexes in a list may appear
  interface    : for each interface block, `require` regexes must match and `forbid` regexes must not,
                 optionally only for interfaces whose header matches `select`

Rules may carry `remediation` (shown in the report) and `reference` (e.g. a CIS/IEC 62443 pointer).
The engine is config-format-agnostic: it works on indented, block-structured CLI configs
(Cisco IOS/NX-OS style and anything close). Pack authors mark dialects they haven't verified.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import yaml

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 10, "low": 4, "info": 0}


@dataclass
class Rule:
    id: str
    title: str
    severity: str = "medium"
    check: str = "present"
    pattern: Optional[str] = None
    patterns: list = field(default_factory=list)
    select: Optional[str] = None
    require: list = field(default_factory=list)
    forbid: list = field(default_factory=list)
    remediation: str = ""
    reference: str = ""
    flags_i: bool = True

    @property
    def _flags(self):
        return re.IGNORECASE | re.MULTILINE if self.flags_i else re.MULTILINE


@dataclass
class RulePack:
    name: str
    description: str
    dialect: str
    verified: bool
    rules: list


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    status: str          # pass | fail | error
    detail: str = ""
    remediation: str = ""
    reference: str = ""
    scope: str = ""      # e.g. interface name

    def as_dict(self):
        return self.__dict__.copy()


def load_pack(path: str) -> RulePack:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    rules = []
    for r in data.get("rules", []):
        rules.append(Rule(
            id=str(r["id"]), title=r.get("title", r["id"]), severity=r.get("severity", "medium").lower(),
            check=r.get("check", "present"), pattern=r.get("pattern"), patterns=r.get("patterns", []) or [],
            select=r.get("select"), require=r.get("require", []) or [], forbid=r.get("forbid", []) or [],
            remediation=r.get("remediation", ""), reference=r.get("reference", ""),
            flags_i=r.get("case_insensitive", True)))
    return RulePack(name=data.get("name", path), description=data.get("description", ""),
                    dialect=data.get("dialect", "generic"), verified=bool(data.get("verified", False)), rules=rules)


# ---------------------------------------------------------------- interface splitting
def split_interfaces(config: str) -> list[tuple[str, str]]:
    """Return (header_line, block_text) for each top-level 'interface ...' block."""
    lines = config.splitlines()
    blocks, cur_head, cur = [], None, []
    for ln in lines:
        if re.match(r"^\s*interface\s+\S", ln, re.IGNORECASE):
            if cur_head is not None:
                blocks.append((cur_head, "\n".join(cur)))
            cur_head, cur = ln.strip(), [ln]
        elif cur_head is not None:
            # a non-indented, non-blank line that isn't part of the interface ends the block
            if ln.strip() and not ln[:1].isspace() and not re.match(r"^\s", ln):
                blocks.append((cur_head, "\n".join(cur)))
                cur_head, cur = None, []
            else:
                cur.append(ln)
    if cur_head is not None:
        blocks.append((cur_head, "\n".join(cur)))
    return blocks


# ---------------------------------------------------------------- the checks
def _search(pattern: str, text: str, flags) -> bool:
    try:
        return re.search(pattern, text, flags) is not None
    except re.error:
        return False


def apply_rule(rule: Rule, config: str) -> list[Finding]:
    f = rule._flags
    try:
        if rule.check == "present":
            ok = _search(rule.pattern or "", config, f)
            return [_fin(rule, "pass" if ok else "fail",
                         "" if ok else f"required configuration not found: /{rule.pattern}/")]
        if rule.check == "absent":
            hit = _search(rule.pattern or "", config, f)
            return [_fin(rule, "fail" if hit else "pass",
                         f"disallowed configuration present: /{rule.pattern}/" if hit else "")]
        if rule.check == "present_all":
            missing = [p for p in rule.patterns if not _search(p, config, f)]
            return [_fin(rule, "fail" if missing else "pass",
                         "missing: " + ", ".join(f"/{m}/" for m in missing) if missing else "")]
        if rule.check == "absent_all":
            hits = [p for p in rule.patterns if _search(p, config, f)]
            return [_fin(rule, "fail" if hits else "pass",
                         "present: " + ", ".join(f"/{h}/" for h in hits) if hits else "")]
        if rule.check == "interface":
            return _interface_rule(rule, config, f)
        return [_fin(rule, "error", f"unknown check type '{rule.check}'")]
    except Exception as e:  # a rule must never crash the whole audit
        return [_fin(rule, "error", f"rule error: {e}")]


def _interface_rule(rule: Rule, config: str, f) -> list[Finding]:
    out = []
    ifaces = split_interfaces(config)
    scoped = [(h, b) for h, b in ifaces if not rule.select or _search(rule.select, h, f)]
    if not scoped:
        return [_fin(rule, "info", "no matching interfaces", scope="(none)")]
    for head, block in scoped:
        name = head
        problems = []
        problems += [f"missing /{p}/" for p in rule.require if not _search(p, block, f)]
        problems += [f"has /{p}/" for p in rule.forbid if _search(p, block, f)]
        out.append(_fin(rule, "fail" if problems else "pass", "; ".join(problems), scope=name))
    return out


def _fin(rule: Rule, status: str, detail: str = "", scope: str = "") -> Finding:
    return Finding(rule.id, rule.title, rule.severity, status, detail,
                   rule.remediation if status == "fail" else "", rule.reference, scope)


def audit(config: str, pack: RulePack) -> dict:
    findings: list[Finding] = []
    for rule in pack.rules:
        findings += apply_rule(rule, config)
    fails = [f for f in findings if f.status == "fail"]
    by_sev = {s: sum(1 for f in fails if f.severity == s) for s in SEVERITIES}
    penalty = sum(SEV_WEIGHT.get(f.severity, 0) for f in fails)
    score = max(0, 100 - penalty)
    return {
        "pack": pack.name, "dialect": pack.dialect, "verified": pack.verified,
        "score": score,
        "summary": {"rules": len(pack.rules), "checks": len(findings),
                    "passed": sum(1 for f in findings if f.status == "pass"),
                    "failed": len(fails), "errors": sum(1 for f in findings if f.status == "error"),
                    "by_severity": {k: v for k, v in by_sev.items() if v}},
        "findings": [f.as_dict() for f in sorted(findings, key=lambda x: (x.status != "fail", SEVERITIES.index(x.severity) if x.severity in SEVERITIES else 9, x.rule_id))],
    }
