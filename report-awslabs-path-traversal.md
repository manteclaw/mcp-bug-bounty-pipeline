> **Status note (added Nov 2026):** this report was prepared in May 2026 but **never submitted** — follow-up analysis judged the finding a false positive for practical exploitation (see `verdict-summary.md`). No bounty was paid. Kept as a worked example.

# Bug Bounty Report: Path Traversal in awslabs/mcp aws-healthomics-mcp-server

## Metadata

| Field | Value |
|---|---|
| **Reporter** | manteclaw@proton.me |
| **Repository** | https://github.com/awslabs/mcp |
| **Affected Package** | `awslabs.aws-healthomics-mcp-server` |
| **Vulnerability Type** | Path Traversal (CWE-22) / Arbitrary File Read |
| **Severity** | Medium (CVSS ~5.3) |
| **Status** | Pending submission to huntr.com |

---

## Executive Summary

The `create_workflow()` MCP tool in `awslabs/aws-healthomics-mcp-server` accepts a `readme` parameter that is passed directly to Python's `open()` function without path traversal sanitization. While the code checks for a `.md` file extension, this check does not prevent directory traversal sequences (`../`). An attacker can read arbitrary `.md` files anywhere on the filesystem via path traversal, and can bypass the extension restriction entirely using symbolic links.

This is inconsistent with the `content_resolver.py` module in the same codebase, which **does** call `validate_local_path()` to block traversal sequences.

---

## Vulnerability Description

### Location

**File:** `src/aws-healthomics-mcp-server/awslabs/aws_healthomics_mcp_server/utils/validation_utils.py`

**Lines:**
- `detect_readme_input_type()`: lines 45-63
- `validate_readme_input()`: lines 452-505

**Permalink (vulnerable `open()` call):**
```
https://github.com/awslabs/mcp/blob/main/src/aws-healthomics-mcp-server/awslabs/aws_healthomics_mcp_server/utils/validation_utils.py#L490
```

### Root Cause

In `validate_readme_input()`, when the `readme` parameter is detected as a local file:

```python
elif input_type == ReadmeInputType.LOCAL_FILE:
    try:
        with open(readme, 'r', encoding='utf-8') as f:  # <-- NO path sanitization!
            content = f.read()
        return (content, None)
```

The `detect_readme_input_type()` function only checks:
1. If the path starts with `s3://` → S3 URI
2. If the path ends with `.md` AND `os.path.isfile()` returns True → LOCAL_FILE
3. Otherwise → MARKDOWN_CONTENT

**The `.md` extension check is not path sanitization.** The raw path string (including any `../` sequences) is passed directly to `open()`.

### Contrast with Secure Code

In the same codebase, `content_resolver.py` properly sanitizes paths:

```python
def detect_content_input_type(value: str) -> ContentInputType:
    if value.startswith('s3://'):
        return ContentInputType.S3_URI
    try:
        validate_local_path(value)  # <-- Blocks ../ traversal!
        if os.path.isfile(value) or os.path.isdir(value):
            return ContentInputType.LOCAL_FILE
    except ValueError:
        logger.debug(f'Path traversal detected, treating as inline content')
    return ContentInputType.INLINE_CONTENT
```

`validate_local_path()` (defined in `path_utils.py`) raises `ValueError` if the path contains `..` components. This same validation should be applied to `readme` inputs.

---

## Impact Assessment

### Direct Impact
- **Arbitrary `.md` file read**: Any `.md` file on the filesystem can be read via path traversal. Examples:
  - `../../../home/user/.aws/credentials.md`
  - `../../../var/log/application.md`
  - `../../../opt/server/config/secrets.md`

### Bypass Impact
- **Symlink bypass**: An attacker with local filesystem access can create a symlink `link.md -> /etc/passwd` and read any file regardless of extension.

### Secondary Impact
- The exfiltrated README content is passed to AWS HealthOmics API calls, potentially leaking sensitive data to cloud services.
- The MCP server may run with elevated privileges in some deployments, expanding the attack surface.

### CVSS 3.1 Estimate
| Metric | Value |
|---|---|
| Attack Vector | Network (via MCP client) |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality | Low |
| Integrity | None |
| Availability | None |
| **Overall** | **~5.3 (Medium)** |

---

## Proof of Concept

See: `projects/bounty/poc-awslabs-path-traversal.py`

### PoC 1: Path Traversal via `.md` file

```
$ python3 poc-awslabs-path-traversal.py
[+] Payload: readme='../../secret_area/secret.md'
[+] Detected type: LOCAL_FILE
[+] EXFILTRATED CONTENT:
SECRET_DATA: AWS_ACCESS_KEY_ID=[REDACTED]
[*] Vulnerability confirmed: Arbitrary .md file read via path traversal
```

### PoC 2: Symlink Bypass

```
[+] Created symlink: link.md -> /tmp/credentials
[+] Payload: readme='link.md'
[+] Detected type: LOCAL_FILE
[+] EXFILTRATED CONTENT:
[default]
aws_access_key_id = [REDACTED-EXAMPLE-KEY-ID]
[*] Vulnerability confirmed: Arbitrary file read via symlink + .md extension
```

### PoC 3: Simulated MCP Tool Call

```json
{
  "tool": "create_workflow",
  "params": {
    "name": "exfil-workflow",
    "description": "Legitimate sounding workflow",
    "readme": "../../../etc/passwd.md",
    "definition_source": "..."
  }
}
```

---

## Fix Suggestion

Apply the same path sanitization used in `content_resolver.py` before calling `open()`:

```python
from awslabs.aws_healthomics_mcp_server.utils.path_utils import validate_local_path

async def validate_readme_input(ctx: Context, readme: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    # ... existing code ...
    
    elif input_type == ReadmeInputType.LOCAL_FILE:
        # FIX: Add path traversal sanitization
        try:
            validate_local_path(readme)
        except ValueError as e:
            error_message = f'Readme path contains traversal sequences: {readme}'
            logger.error(error_message)
            await ctx.error(error_message)
            raise ValueError(error_message) from e
        
        try:
            with open(readme, 'r', encoding='utf-8') as f:
                content = f.read()
            return (content, None)
        except FileNotFoundError:
            # ... existing error handling ...
```

Alternatively, resolve to an absolute path and ensure it stays within an allowed directory:

```python
from pathlib import Path

# Only allow reading from a designated safe directory
SAFE_README_DIR = Path('/allowed/readme/directory').resolve()

resolved = Path(readme).resolve()
if SAFE_README_DIR not in resolved.parents and resolved != SAFE_README_DIR:
    raise ValueError(f'Readme path must be within {SAFE_README_DIR}')
```

---

## Occurrences

1. **Primary occurrence** - `open()` without sanitization:
   - https://github.com/awslabs/mcp/blob/main/src/aws-healthomics-mcp-server/awslabs/aws_healthomics_mcp_server/utils/validation_utils.py#L490

2. **Detection logic** - Missing traversal check in `detect_readme_input_type()`:
   - https://github.com/awslabs/mcp/blob/main/src/aws-healthomics-mcp-server/awslabs/aws_healthomics_mcp_server/utils/validation_utils.py#L45-L63

---

## References

- [Huntr Open Source Vulnerability Form](https://huntr.com/bounties/disclose/opensource)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [awslabs/mcp repository](https://github.com/awslabs/mcp)
- [Secure implementation in content_resolver.py](https://github.com/awslabs/mcp/blob/main/src/aws-healthomics-mcp-server/awslabs/aws_healthomics_mcp_server/utils/content_resolver.py)

---

## Timeline

| Date | Event |
|---|---|
| 2026-05-07 | Vulnerability identified and PoC developed |
| 2026-05-07 | Bounty report prepared |
| 2026-05-07 | Pending submission to huntr.com |

## Submission Status

**Status: BLOCKED — Authentication Required**

### Attempted Platforms

1. **huntr.com** (Primary target)
   - URL: https://huntr.com/bounties/disclose/opensource
   - Result: **Form requires login** — "Please log in to continue. By logging in you agree to our terms of service."
   - All form fields and submit button are disabled until authenticated
   - huntr.com appears to accept AI/ML open-source repos of all sizes (up to $1,500 + CVE)
   - **Blocker:** No existing account; account creation requires email verification

2. **AWS Security (alternative)**
   - Contact: aws-security@amazon.com
   - Per: https://github.com/awslabs/mcp/security
   - Policy: "notify AWS/Amazon Security via our vulnerability reporting page or directly via email"
   - **Blocker:** Email submission requires SMTP credentials; not configured

### Recommended Next Steps

1. **huntr.com (preferred for bounty)**
   - Create account at huntr.com (supports GitHub OAuth)
   - Complete the Open Source Vulnerability Form with the data in this report
   - Repository: `https://github.com/awslabs/mcp`
   - Package Manager: `pypi`
   - Version: `current main branch`
   - Vulnerability Type: `Path Traversal`
   - CVSS: ~5.3 (Medium)
   - Occurrences: Two permalinks listed above

2. **AWS Security (responsible disclosure)**
   - Email `aws-security@amazon.com` with this report
   - Subject: `Security Vulnerability: Path Traversal in awslabs/aws-healthomics-mcp-server`
   - This ensures AWS is notified regardless of bounty outcome

### Files Delivered

| File | Description |
|---|---|
| `projects/bounty/poc-awslabs-path-traversal.py` | Working PoC with 3 demonstrations |
| `projects/bounty/report-awslabs-path-traversal.md` | Full bounty report with fix suggestion |

---

*Report prepared by manteclaw@proton.me*

