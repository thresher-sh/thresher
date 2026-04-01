# Host Boundary Hardening Spec

Hardens the data path between the Lima VM and the host machine. The VM should be treated as a fully compromised environment — every byte that crosses the boundary back to the host is untrusted input.

## Problem

The host communicates with the VM via `limactl shell` (command execution) and `limactl copy` (file transfer). The SSH transport itself is low-risk — the host is the client, the VM is the server, `plain: true` disables reverse channels, and there are no port forwards or shared mounts.

The real attack surface is **what travels over the connection**:

### What goes INTO the VM (host → VM)

| Data | Transport | Risk |
|------|-----------|------|
| Provisioning scripts | `ssh_copy_to` | None — host-authored, static |
| Firewall/lockdown scripts | `ssh_copy_to` | None — host-authored, static |
| `ANTHROPIC_API_KEY` | Shell export via `ssh_exec` | **Medium** — readable by any process in the VM |
| Analysis prompts | `ssh_write_file` | None — host-authored, static |
| Enriched findings JSON | `ssh_write_file` | Low — host-authored from scanner output already parsed |

### What comes OUT of the VM (VM → host)

| Data | Transport | Risk |
|------|-----------|------|
| Scanner JSON output | `ssh_exec` stdout (via `cat`) | **High** — attacker-influenced content parsed as JSON on host |
| Final report directory | `ssh_copy_from` (recursive) | **High** — arbitrary files, filenames, symlinks, sizes |
| Dependency manifest | `ssh_exec` stdout (via `cat`) | **High** — attacker-influenced JSON |

### Current vulnerabilities

1. **`ssh_copy_from` does no validation** — `cli.py:290` copies the entire report directory from the VM to the host with `limactl copy -r`. A compromised VM could write:
   - Symlinks pointing to `/etc/passwd` or other host paths (limactl follows symlinks during copy)
   - Filenames with path traversal (`../../.bashrc`)
   - Extremely large files (disk exhaustion)
   - Unexpected file types (executables, scripts)

2. **Scanner JSON parsed without size limits** — each scanner reads its output via `ssh_exec(vm_name, f"cat {output_path}")` and passes it to `json.loads()`. A compromised VM could write a multi-GB JSON file that exhausts host memory during parsing.

3. **`ssh_exec` stdout is trusted** — commands like `cat /opt/scan-results/grype.json` return stdout that's parsed as JSON. The VM controls what's in those files.

4. **API key exposure** — `ANTHROPIC_API_KEY` is passed as a shell export. Any process in the VM can read it from `/proc/<pid>/environ` or by inspecting the bash process environment.

## Solution: Validate Everything at the Boundary

### 1. Sanitize `ssh_copy_from` Output

Add a post-copy validation step that runs **on the host** after `limactl copy -r` completes. This is the most critical hardening since it's where arbitrary files land on the host filesystem.

**New function**: `ssh_copy_from_safe()` in `ssh.py`

```python
import stat

# Maximum total size of copied data (500 MB)
MAX_COPY_SIZE_BYTES = 500 * 1024 * 1024

# Maximum individual file size (50 MB)
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024

# Allowed file extensions in report output
ALLOWED_EXTENSIONS = {".json", ".md", ".txt", ".csv", ".log", ".sarif"}


def ssh_copy_from_safe(vm_name: str, remote_path: str, local_path: str) -> None:
    """Copy from VM and validate the result on the host side.

    After copying, walks the destination and:
    - Removes symlinks (logs a warning)
    - Rejects path traversal in filenames
    - Enforces file size limits
    - Rejects unexpected file types
    - Strips executable bits
    """
    # Copy to a temporary staging directory first
    staging = Path(tempfile.mkdtemp(prefix="vm-copy-"))
    try:
        ssh_copy_from(vm_name, remote_path, str(staging))
        _validate_copied_tree(staging)
        # Move validated files to final destination
        shutil.copytree(staging, local_path, dirs_exist_ok=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _validate_copied_tree(root: Path) -> None:
    """Walk a directory tree and reject or neutralize dangerous content."""
    total_size = 0

    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)

        # Reject path traversal
        if ".." in relative.parts:
            raise SSHError(f"Path traversal detected: {relative}")

        # Remove symlinks
        if path.is_symlink():
            logger.warning("Removing symlink from VM output: %s", relative)
            path.unlink()
            continue

        if path.is_file():
            # Check individual file size
            size = path.stat().st_size
            if size > MAX_FILE_SIZE_BYTES:
                raise SSHError(
                    f"File too large from VM: {relative} ({size} bytes)"
                )
            total_size += size

            # Check total size
            if total_size > MAX_COPY_SIZE_BYTES:
                raise SSHError(
                    f"Total copy size exceeds {MAX_COPY_SIZE_BYTES} bytes"
                )

            # Check extension
            if path.suffix.lower() not in ALLOWED_EXTENSIONS:
                logger.warning(
                    "Removing unexpected file type from VM output: %s",
                    relative,
                )
                path.unlink()
                continue

            # Strip executable bits
            current_mode = path.stat().st_mode
            path.chmod(current_mode & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
```

**Where to use**: Replace the `ssh_copy_from` call in `cli.py:290` with `ssh_copy_from_safe`.

### 2. Bounded JSON Parsing

Add a safe JSON reader that limits input size before parsing. All scanner output and manifest reads should use this.

**New function**: `safe_json_loads()` in a shared utility

```python
# Maximum JSON payload size (10 MB)
MAX_JSON_SIZE_BYTES = 10 * 1024 * 1024


def safe_json_loads(text: str, source: str = "unknown") -> dict | list | None:
    """Parse JSON with size limit and error containment.

    Args:
        text: Raw JSON string.
        source: Label for logging (e.g. "grype output").

    Returns:
        Parsed JSON, or None if parsing fails.

    Raises:
        SSHError: If the payload exceeds the size limit.
    """
    if len(text) > MAX_JSON_SIZE_BYTES:
        raise SSHError(
            f"JSON payload from VM too large ({len(text)} bytes) "
            f"from source: {source}"
        )
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.error("Failed to parse JSON from source: %s", source)
        return None
```

**Where to use**: Replace every `_safe_parse_json()` / `json.loads()` call that processes VM output across all scanner modules.

### 3. Limit `ssh_exec` Output Size

The current `ssh_exec` accumulates stdout line by line with no limit. A compromised VM could stream gigabytes of output.

**Change in `ssh_exec`**:

```python
MAX_STDOUT_BYTES = 50 * 1024 * 1024  # 50 MB

# In the selector loop:
stdout_size = 0
for key, _ in events:
    line = key.fileobj.readline()
    if not line:
        sel.unregister(key.fileobj)
        continue
    if key.fileobj is proc.stdout:
        stdout_size += len(line)
        if stdout_size > MAX_STDOUT_BYTES:
            proc.kill()
            proc.wait()
            raise SSHError(
                f"VM output exceeded {MAX_STDOUT_BYTES} bytes, killed process"
            )
        stdout_lines.append(line)
```

### 4. Reduce API Key Exposure Window

The API key is currently passed as a shell environment variable for the entire SSH session. This means any process running in the VM during that session can read it.

**Current** (`lima.py`):
```python
ssh_exec(vm_name, "run_analyst.sh", env={"ANTHROPIC_API_KEY": key})
```

**Improvements**:

**Option A: Write key to a tmpfs file, read and delete**

```python
# Write key to a tmpfs-backed file (never touches disk)
ssh_exec(vm_name, f"echo '{quoted_key}' > /dev/shm/.api_key && chmod 600 /dev/shm/.api_key")

# The analysis script reads from the file, then:
ssh_exec(vm_name, "ANTHROPIC_API_KEY=$(cat /dev/shm/.api_key) run_analysis.sh; rm -f /dev/shm/.api_key")
```

This reduces the window — the key is in a file briefly, then deleted. It's not in the persistent environment of a long-running shell.

**Option B: Pass via stdin** (more secure but requires script changes)

```python
# Pipe the key via stdin so it never appears in process arguments or env
ssh_exec(vm_name, "read -r ANTHROPIC_API_KEY; export ANTHROPIC_API_KEY; run_analysis.sh",
         stdin=key)
```

**Recommendation**: Option A is simpler and fits the current architecture. The key exposure window shrinks from "entire scan session" to "duration of the analysis command."

**Note**: Neither option fully prevents a rootkit already running in the VM from intercepting the key (it could hook the read syscall, watch `/dev/shm`, etc.). The real defense is that the VM is ephemeral — it's destroyed after each scan, so a compromised key has a very short useful lifetime. Consider rotating or scoping the API key per scan if the threat model demands more.

### 5. Validate Report Structure Before Use

After copying the report directory back and validating files, verify the expected structure exists before any host-side processing consumes it.

```python
EXPECTED_REPORT_FILES = [
    "findings.json",
    "executive-summary.md",
    "detailed-report.md",
]

def validate_report_structure(report_dir: Path) -> None:
    """Verify the copied report contains expected files and nothing extra."""
    present = {p.relative_to(report_dir) for p in report_dir.rglob("*") if p.is_file()}
    expected = {Path(f) for f in EXPECTED_REPORT_FILES}

    missing = expected - present
    if missing:
        logger.warning("Report missing expected files: %s", missing)

    # Log unexpected files (already filtered by extension in copy step,
    # but defense in depth)
    known_prefixes = {"scan-results/", "findings.json", "executive-summary.md",
                      "detailed-report.md", "synthesis-findings.md",
                      "sbom.json", "synthesis_input.md"}
    for f in present:
        if not any(str(f).startswith(p) for p in known_prefixes):
            logger.warning("Unexpected file in report: %s", f)
```

## How the Layers Work Together

| Attack | Mitigation |
|--------|-----------|
| Symlink in report dir pointing to host `/etc/passwd` | `_validate_copied_tree` removes symlinks before moving to final destination |
| Filename `../../.bashrc` in report output | Path traversal check rejects `..` in any path component |
| 10 GB `grype.json` to exhaust host memory | `safe_json_loads` rejects payloads > 10 MB; `ssh_exec` kills process at 50 MB stdout |
| Executable dropped in report dir | Extension allowlist removes non-`{json,md,txt,csv,log,sarif}` files; executable bits stripped |
| Malformed JSON causing parser hang | `json.loads` doesn't hang (it's not a streaming parser), size limit prevents memory exhaustion |
| API key stolen by malware in VM | Reduced exposure window via tmpfs; ephemeral VM destroyed after scan; consider per-scan key rotation |
| VM streams infinite stdout to exhaust host memory | `ssh_exec` enforces 50 MB stdout cap |

## Files Modified

| File | Change |
|------|--------|
| `src/threat_scanner/vm/ssh.py` | Add `ssh_copy_from_safe`, `_validate_copied_tree`, stdout size limit in `ssh_exec` |
| `src/threat_scanner/vm/safe_io.py` (new) | `safe_json_loads`, `validate_report_structure`, constants for size limits and allowed extensions |
| `src/threat_scanner/cli.py` | Use `ssh_copy_from_safe` instead of `ssh_copy_from` |
| `src/threat_scanner/scanners/*.py` | Replace `_safe_parse_json` / `json.loads` with `safe_json_loads` across all scanner modules |
| `src/threat_scanner/agents/analyst.py` | Use `safe_json_loads` for parsing agent output |
| `src/threat_scanner/agents/adversarial.py` | Use `safe_json_loads` for parsing verification output |
| `src/threat_scanner/vm/lima.py` | API key handling — write to `/dev/shm`, read-and-delete pattern |

## Implementation Order

1. Add `safe_json_loads` utility and size constants
2. Add stdout size limit to `ssh_exec`
3. Add `ssh_copy_from_safe` with staging directory and validation
4. Update `cli.py` to use safe copy
5. Update all scanner modules to use `safe_json_loads`
6. Update agent output parsing to use `safe_json_loads`
7. Implement API key tmpfs pattern
8. Add `validate_report_structure` post-copy check

## Open Questions

1. **`limactl copy` symlink behavior**: Does `limactl copy -r` follow symlinks in the VM, or does it copy them as symlinks? If it copies as symlinks, the host-side validation catches them. If it follows them, the VM could cause limactl to read arbitrary VM files — but that's contained to the VM filesystem. Need to test.

2. **Report size limits**: The 50 MB per-file and 500 MB total limits are generous. In practice, scan reports should be well under 10 MB. Tighter limits could be set once we have production data on typical report sizes.

3. **Scanner output via stdout vs. file**: Currently, scanners write output to a file in the VM, then we `cat` it back via `ssh_exec`. An alternative is to have scanners write to stdout directly, which avoids the extra file read. But this changes the scanner invocation pattern — evaluate in the context of the dependency resolution container changes.
