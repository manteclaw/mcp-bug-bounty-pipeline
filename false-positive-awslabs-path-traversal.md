# awslabs/mcp Path Traversal — False Positive Analysis

**Scanner Finding:** Path traversal in `create_workflow()` via the `readme` parameter, which is passed to `open(readme, 'r')`.
**Location:** `src/aws-healthomics-mcp-server/awslabs/aws_healthomics_mcp_server/tools/workflow_management.py`
**Status:** ⚠️ **FALSE POSITIVE** (for practical exploitation)

---

## Why It's Flagged

The scanner sees:

```python
readme_markdown, readme_uri = await validate_readme_input(ctx, readme)
```

And inside `validation_utils.py`:

```python
elif input_type == ReadmeInputType.LOCAL_FILE:
    with open(readme, 'r', encoding='utf-8') as f:
        content = f.read()
```

This is a raw `open()` on user-controlled input. No explicit path traversal sanitization (no `validate_local_path()` call) before the file is opened.

---

## Why It's Not Exploitable (Remote)

### 1. Input Type Detection Gate

`detect_readme_input_type()` classifies input into three categories:

```python
def detect_readme_input_type(readme: str) -> ReadmeInputType:
    if readme.startswith('s3://'):
        return ReadmeInputType.S3_URI
    if readme.lower().endswith('.md') and os.path.isfile(readme):
        return ReadmeInputType.LOCAL_FILE
    return ReadmeInputType.MARKDOWN_CONTENT
```

**To hit the `LOCAL_FILE` branch, ALL of these must be true:**
- The string does NOT start with `s3://`
- The string ends with `.md` (case-insensitive)
- `os.path.isfile(readme)` returns `True`

### 2. The `.md` Extension Check

An attacker cannot read `/etc/passwd`, `/proc/self/environ`, `~/.aws/credentials`, or other classic targets because none of these end in `.md`. The extension check is hard — not even a null byte bypass works because Python `open()` would reject it.

### 3. The `os.path.isfile()` Check

Even if the attacker guesses a `.md` file exists somewhere sensitive (e.g., `../../../..$HOME/notes.md`), `os.path.isfile()` must return `True`. If the file doesn't exist, the input falls through to `MARKDOWN_CONTENT` and is treated as raw markdown text — never opened.

### 4. No Symlink Creation Vector

A classic bypass would be:
1. Attacker creates `evil.md` as a symlink to `/etc/passwd`
2. Passes `evil.md` as `readme`
3. `os.path.isfile('evil.md')` → `True` (target is a regular file)
4. `open('evil.md')` reads `/etc/passwd`

**This requires filesystem write access on the server**, which a remote attacker does not have in the standard MCP server deployment model.

---

## Comparison with `definition_source` (Which IS Protected)

The `definition_source` parameter flows through `resolve_single_content()`, which **does** call `validate_local_path()` from `path_utils.py`:

```python
def validate_local_path(path: str) -> None:
    if path.startswith('../') or '/../' in path or path == '..' or path.endswith('/..'):
        raise ValueError(f'Path contains traversal sequences: {path}')
    parts = os.path.normpath(path).split(os.sep)
    if '..' in parts:
        raise ValueError(f'Path contains traversal sequences: {path}')
```

The `readme` path bypasses this entirely — **inconsistent defense-in-depth**.

---

## Verdict

| Criterion | Assessment |
|-----------|------------|
| Raw `open()` on user input? | Yes |
| Path traversal sanitization? | No |
| Practical remote exploit? | **No** |
| `.md` extension gate? | Yes — blocks all classic targets |
| Existence gate (`os.path.isfile`)? | Yes — blocks guessing |
| Defense-in-depth gap? | Yes — should call `validate_local_path()` |

**Conclusion:** The scanner is technically correct that there's an unsanitized path opening. However, the `.md` extension requirement + existence check make this **non-exploitable as a path traversal vulnerability** in standard deployments. The `readme` parameter is designed to accept local `.md` files for README documentation, and the type detection logic accidentally provides sufficient guards against remote exploitation.

---

## Recommendation (if reporting to AWS)

Close as **low severity / defense-in-depth** rather than a real path traversal. Suggest adding `validate_local_path(readme)` inside `validate_readme_input()` for consistency with `content_resolver.py`, even though it's not practically exploitable.

---

*Analyzed 2026-05-07*
