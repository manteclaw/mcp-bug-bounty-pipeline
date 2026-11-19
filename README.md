# MCP Bug-Bounty Pipeline

A batch-scanning workflow for hunting security issues in MCP (Model Context Protocol)
servers, with worked triage write-ups. It wraps existing scanners — it is **not** a
scanner itself.

## ⚠️ Honest status, up front

- The headline finding from the first scan run — a path traversal in
  `awslabs/mcp` (`aws-healthomics-mcp-server`, `create_workflow()` via the `readme`
  parameter) — was judged a **false positive** for practical exploitation. The `.md`
  extension gate plus an `os.path.isfile()` existence check block remote exploitation;
  only a symlink bypass requiring local filesystem write access remains, and the
  `readme` path is missing the `validate_local_path()` sanitizer its sibling code
  uses. Full analysis: [`false-positive-awslabs-path-traversal.md`](false-positive-awslabs-path-traversal.md)
  and [`verdict-summary.md`](verdict-summary.md).
- **No bounty was ever submitted or paid.** The report in
  [`report-awslabs-path-traversal.md`](report-awslabs-path-traversal.md) was prepared
  but never filed (huntr.com submission was blocked on account creation; the finding
  was then triaged as a false positive).
- Scanner output is noisy: 466 findings across the first two targets, with a high
  false-positive rate (~30% in the reference eltociear pipeline). Triage is the work;
  scanning is the easy part.

## What it is

- [`scan-batch.sh`](scan-batch.sh) — batch-run `mcp-audit sast` over every target in
  `targets.txt`, filter to HIGH/CRITICAL, and write a per-run JSON summary.
- [`.github/workflows/mcp-security-audit.yml`](.github/workflows/mcp-security-audit.yml) —
  weekly GitHub Actions workflow: clone a target repo, scan it, upload results.
- [`MCP-BUG-BOUNTY-PIPELINE.md`](MCP-BUG-BOUNTY-PIPELINE.md) — the original May 2026
  setup report: scanner comparison, submission workflow for huntr.com / MSRC /
  Google VRP, and the eltociear reference pipeline.
- [`scans/summary-2026-05-07.md`](scans/summary-2026-05-07.md) — sanitized aggregate
  counts from the first scan runs. Raw scan JSONs are deliberately **not** published:
  scanner evidence embeds code snippets harvested from scanned third-party repos,
  which can contain credential-shaped strings.

## Who it is for

- Security-minded developers auditing MCP servers they run or depend on.
- Bug-bounty hunters scouting MCP targets — with the caveat above: expect to spend
  most of your time triaging scanner noise, and verify every finding by hand before
  reporting anything.

## Install

```bash
# mcp-audit (primary scanner) + Semgrep
pipx install mcp-audit-scanner
pip install semgrep
# Fix typer/click compatibility if needed:
pip install 'typer<0.13'

# Optional: agent-audit scans MCP config files (not source)
npm install -g @piiiico/agent-audit
```

Requires Python 3.12+ and `jq` (for severity filtering in `scan-batch.sh`).

## Usage

```bash
# 1. Clone a public target and list its path in targets.txt
git clone https://github.com/awslabs/mcp.git /tmp/awslabs-mcp

# 2. Scan everything in targets.txt (HIGH and above by default)
MIN_SEVERITY=HIGH ./scan-batch.sh targets.txt

# 3. Triage: read the filtered JSONs in scans/, verify each finding by hand,
#    and write up the verdict before reporting anything anywhere.
#    See false-positive-awslabs-path-traversal.md for what good triage looks like.
```

### The write-ups

| File | What it is |
|---|---|
| `verdict-summary.md` | One-page verdict: false positive, and why |
| `false-positive-awslabs-path-traversal.md` | Full false-positive analysis with code references |
| `report-awslabs-path-traversal.md` | The bounty report as prepared (never submitted) |
| `poc-awslabs-path-traversal.py` | Executable PoC demonstrating the `.md`/existence gates |
| `poc-path-traversal-awslabs-mcp.py` | Payload generator + remediation sketch |
| `dgld-post-mortem.md` | Post-mortem of the Feb 2026 DGLD Base bridge exploit (phantom deposits / unbacked minting) |

Run the PoCs locally — they only touch temp files, no network, no real AWS calls:

```bash
python3 poc-awslabs-path-traversal.py
python3 poc-path-traversal-awslabs-mcp.py
```

## Limits

- **This pipeline wraps external scanners** (`mcp-audit` + Semgrep rules). It finds
  candidate issues; it does not confirm them.
- **High false-positive rate.** Docstring examples, non-English tool descriptions,
  build scripts, and URL constants all get flagged. Every finding needs manual review.
- **Submission is manual.** huntr.com, MSRC, and Google VRP all require browser-based
  submission; there is no API/CLI path.
- **No live scanning in this repo.** The scan outputs here are a May 2026 snapshot;
  re-run the pipeline for current results.

## License

MIT — see [LICENSE](LICENSE).
