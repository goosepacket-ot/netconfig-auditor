# netconfig-auditor

**Audit a network device configuration against a hardening baseline written in plain YAML — scored findings, remediation and a report, no appliance required.**

Point it at a saved `show running-config` and a rule pack, and it tells you what's weak and how to fix it:

```
$ ncaudit run switch.cfg --pack rulepacks/cisco-ios-baseline.yaml --out report/
PLANT-ACCESS-SW1: score 0/100 — 17 failed of 32 checks
  [CRITICAL] Enable secret (not enable password) is used
  [HIGH    ] AAA new-model is enabled
  [HIGH    ] No SNMP community 'public' or 'private'
  [HIGH    ] VTY lines use SSH transport only (no Telnet)
  [MEDIUM  ] Logging to a syslog server is configured
  ...
reports: report/audit.json, report/audit.md, report/audit.html
```

The rules live in **YAML, not code**, so a network or OT engineer can read, fork and extend the baseline without touching Python. The engine is config-format-agnostic (it works on indented, block-structured CLI configs), ships with a verified **Cisco IOS** baseline, and includes a **Hirschmann HiOS** draft pack to show how to target industrial switches.

See a rendered example in [`docs/example-report/`](docs/example-report/).

> A passing audit means the config matches *this baseline* — not that the device is secure. The baseline is a starting point; review it against your own standard and site exceptions.

## Why I built it

On an OT site you rarely get to run a scanner against live switches — but you can almost always get a config export. After 5+ years I have reviewed those by eye more times than I can count, and the same dozen things are always wrong: Telnet still on, SNMP `public`, no syslog, `enable password` instead of `enable secret`. This tool encodes that checklist so the boring 80% is automatic and I can spend the review on the interesting 20%. Keeping the rules in YAML matters: the customer can see exactly what "hardened" means to me, and argue with it.

## Install

```bash
git clone https://github.com/goosepacket/netconfig-auditor
cd netconfig-auditor
pip install -e .
```

Python 3.9+ and PyYAML.

## Use

```bash
# list the bundled rule packs
ncaudit packs

# audit a config
ncaudit run switch.cfg --pack rulepacks/cisco-ios-baseline.yaml --out report/ --device CORE-SW1

# gate in CI: exit 2 if the score is below 80
ncaudit run switch.cfg --pack rulepacks/cisco-ios-baseline.yaml --out report/ --fail-under 80
```

Outputs: `audit.html` (scored, styled), `audit.md` (for a report), `audit.json` (structured).

## Writing a rule pack

A pack is YAML with a header and a list of rules. Each rule is one check:

```yaml
name: My baseline
dialect: cisco-ios
verified: true            # set false if you haven't confirmed the CLI syntax for this OS
rules:
  - id: PWD-001
    title: Enable secret is used
    severity: critical     # critical | high | medium | low | info
    check: present         # present | absent | present_all | absent_all | interface
    pattern: '^enable secret'
    remediation: "Use 'enable secret' instead of 'enable password'."
    reference: CIS Cisco IOS 1.1.2
```

Check types:

| check | passes when |
|---|---|
| `present` | `pattern` appears in the config |
| `absent` | `pattern` does **not** appear |
| `present_all` | every regex in `patterns` appears |
| `absent_all` | none of the regexes in `patterns` appears |
| `interface` | for each interface block (optionally filtered by `select`), all `require` regexes match and no `forbid` regex matches |

Patterns are Python regular expressions, matched multi-line and case-insensitive by default (set `case_insensitive: false` to override). A malformed regex is reported as a rule *error*, never a crash.

## Scoring

Each failed rule subtracts a weight by severity (critical 40, high 20, medium 10, low 4, info 0) from 100; the floor is 0. The score maps to a grade (A ≥ 90 … F < 40). Scoring is intentionally simple and transparent — it's a triage signal, not a risk calculation.

## Bundled packs

- **`cisco-ios-baseline.yaml`** — 15 rules for Cisco IOS / IOS-XE (AAA, SSH-only VTY, no default SNMP, syslog, NTP auth, per-interface BPDU guard / port-security), themed on the CIS Cisco IOS Benchmark. `verified: true`.
- **`hirschmann-hios-baseline.yaml`** — a **draft** for Hirschmann HiOS industrial switches, mapped to IEC 62443-4-2 component requirements. Marked `verified: false`: the patterns illustrate intent but the exact HiOS CLI varies by firmware — **confirm them before relying on a pass.** The report shows a prominent warning for any unverified pack.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

CI runs on Python 3.9–3.12 (`.github/workflows/ci.yml`).

## License

MIT — see [LICENSE](LICENSE).
