"""Shell branding utilities for the Thresher CLI.

All terminal output formatting and ASCII art lives here.
Pure Python — no external dependencies, just ANSI escape sequences.
"""

from __future__ import annotations

# ── ANSI color constants ──────────────────────────────────────────

RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
VIOLET = '\033[38;5;141m'
ARCTIC = '\033[38;5;195m'
GRAY = '\033[38;5;245m'
GREEN = '\033[38;5;114m'
RED = '\033[38;5;203m'
AMBER = '\033[38;5;214m'
WHITE = '\033[38;5;255m'

# ── ASCII art ─────────────────────────────────────────────────────

SPLASH_ART = r"""                                          ___/|
                              ___________/    |
                   __________/                |
               ___/    _____                  |
           ___/   \___/     \                 |
       ___/                  \         ______/
   ___/         _              \______/
  /          __/ \__    ___----~
 |      ,__-~      \--~
 |     /    _,
  \___/  __/
     |  /
     |_/
      ~"""

COMPACT_SHARK = r"""    _/|\___
   /  () \___
  /          \____
 | THRESHER      /
  \      _______/
   \____/"""

# ── Analyst display names (keyed by definition name) ──────────────

ANALYST_DISPLAY_NAMES: dict[str, str] = {
    "paranoid": "The Paranoid",
    "behaviorist": "The Behaviorist",
    "investigator": "The Investigator",
    "pentester-vulns": "Vuln Pentester",
    "pentester-appsurface": "App Pentester",
    "pentester-memory": "Memory Exploiter",
    "infra-auditor": "Infra Auditor",
    "shadowcatcher": "The Shadowcatcher",
}


# ── Print functions ───────────────────────────────────────────────

def print_splash(version: str, url: str) -> None:
    """Print the full splash art with version and URL in violet."""
    lines = SPLASH_ART.split("\n")
    for i, line in enumerate(lines):
        if i == len(lines) - 5:
            # Line with "_," — add title next to it
            print(f"{VIOLET}{line}{RESET}                  {BOLD}{ARCTIC}T H R E S H E R{RESET}")
        elif i == len(lines) - 3:
            # Line with "|  /" — add version info
            print(f"{VIOLET}{line}{RESET}                       {DIM}{version} | {url}{RESET}")
        else:
            print(f"{VIOLET}{line}{RESET}")
    print()


def print_scan_header(repo_url: str) -> None:
    """Print compact shark + scanning target info."""
    print(f"  Scanning: {ARCTIC}{repo_url}{RESET}")
    print()


def print_stage_ok(label: str) -> None:
    """Print [OK] label in green."""
    print(f"  {GREEN}[OK]{RESET} {label}")


def print_stage_running(label: str) -> None:
    """Print [..] label in gray."""
    print(f"  {GRAY}[..]{RESET} {label}")


def print_stage_fail(label: str) -> None:
    """Print [!!] label in red."""
    print(f"  {RED}[!!]{RESET} {label}")


def print_findings_summary(
    p0: int, critical: int, high: int, medium: int, low: int
) -> None:
    """Print formatted findings summary table."""
    print()
    print(f"  {BOLD}{ARCTIC}FINDINGS{RESET}")
    print()
    print(
        f"  {BOLD}{RED}P0{RESET}  {BOLD}{RED}CRIT{RESET}  "
        f"{BOLD}{AMBER}HIGH{RESET}  {BOLD}{AMBER}MED{RESET}   {GRAY}LOW{RESET}"
    )
    print(f"  {p0:>2}    {critical:>2}     {high:>2}    {medium:>2}    {low:>2}")
    print()


def print_report_path(path: str) -> None:
    """Print the report output location."""
    print(f"  Report: {ARCTIC}{path}{RESET}")
    print()


def print_swim_divider() -> None:
    """Print the ~~~_/|~~~ divider in violet."""
    print(f"  {VIOLET}~~~~~~~~~~~_/|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{RESET}")
    print()


def print_analyst_status(number: int, name: str, status: str) -> None:
    """Format and print an analyst status line.

    Args:
        number: Analyst number (1-8).
        name: Display name of the analyst.
        status: One of "done", "running", or "failed".
    """
    # Pad name + dots to align status
    label = f"Analyst {number}: {name} "
    dots = "." * max(1, 40 - len(label))
    label_with_dots = f"{label}{dots}"

    if status == "done":
        color = GREEN
    elif status == "running":
        color = GRAY
    elif status == "failed":
        color = RED
    else:
        color = GRAY

    print(f"    {GRAY}{label_with_dots}{RESET} {color}{status}{RESET}")
