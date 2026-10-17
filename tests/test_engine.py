import os

import pytest

from ncaudit.engine import Rule, RulePack, apply_rule, audit, load_pack, split_interfaces
from ncaudit.report import html_report, markdown, write_all

ROOT = os.path.join(os.path.dirname(__file__), "..")
PACK = os.path.join(ROOT, "rulepacks", "cisco-ios-baseline.yaml")
WEAK = os.path.join(ROOT, "examples", "switch-weak.cfg")
HARD = os.path.join(ROOT, "examples", "switch-hardened.cfg")


def _audit(path):
    return audit(open(path).read(), load_pack(PACK))


def test_present_check():
    r = Rule(id="t", title="t", check="present", pattern=r"^hostname")
    assert apply_rule(r, "hostname X\n")[0].status == "pass"
    assert apply_rule(r, "no host\n")[0].status == "fail"


def test_absent_check():
    r = Rule(id="t", title="t", check="absent", pattern=r"^enable password")
    assert apply_rule(r, "enable password x\n")[0].status == "fail"
    assert apply_rule(r, "enable secret x\n")[0].status == "pass"


def test_present_all_and_absent_all():
    r = Rule(id="t", title="t", check="present_all", patterns=[r"^a$", r"^b$"])
    assert apply_rule(r, "a\nb\n")[0].status == "pass"
    assert apply_rule(r, "a\n")[0].status == "fail"
    r2 = Rule(id="t", title="t", check="absent_all", patterns=[r"public", r"private"])
    assert apply_rule(r2, "community public\n")[0].status == "fail"
    assert apply_rule(r2, "nothing\n")[0].status == "pass"


def test_bad_regex_is_error_not_crash():
    r = Rule(id="t", title="t", check="present", pattern=r"([")
    assert apply_rule(r, "x")[0].status in ("fail", "error")


def test_split_interfaces():
    cfg = "interface Gi0/1\n switchport\n no shutdown\ninterface Gi0/2\n shutdown\n!\nline con 0\n"
    blocks = split_interfaces(cfg)
    names = [h for h, _ in blocks]
    assert names == ["interface Gi0/1", "interface Gi0/2"]
    assert "no shutdown" in dict(blocks)["interface Gi0/1"]


def test_interface_require():
    cfg = "interface Gi0/1\n switchport port-security\ninterface Gi0/2\n switchport mode access\n"
    r = Rule(id="t", title="t", check="interface", select=r"interface Gi",
             require=[r"switchport port-security"])
    res = apply_rule(r, cfg)
    status = {f.scope: f.status for f in res}
    assert status["interface Gi0/1"] == "pass"
    assert status["interface Gi0/2"] == "fail"


def test_weak_scores_zero_hardened_high():
    weak = _audit(WEAK)
    hard = _audit(HARD)
    assert weak["score"] == 0
    assert hard["score"] >= 85
    assert weak["summary"]["failed"] > hard["summary"]["failed"]


def test_weak_has_critical_enable_secret_finding():
    weak = _audit(WEAK)
    crit = [f for f in weak["findings"] if f["severity"] == "critical" and f["status"] == "fail"]
    assert crit and crit[0]["rule_id"] == "PWD-001"


def test_unverified_pack_flag():
    pack = load_pack(os.path.join(ROOT, "rulepacks", "hirschmann-hios-baseline.yaml"))
    assert pack.verified is False
    res = audit("telnet server enable\n", pack)
    assert res["verified"] is False
    assert "not syntax-verified" in html_report(res, "x")


def test_reports_written(tmp_path):
    res = _audit(WEAK)
    paths = write_all(res, str(tmp_path), "SW1")
    assert {os.path.basename(p) for p in paths} == {"audit.json", "audit.md", "audit.html"}
    md = markdown(res, "SW1")
    assert "Config audit" in md and "Failures" in md
    assert "<!doctype html>" in html_report(res, "SW1").lower()
