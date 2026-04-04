"""Shell branding utilities for the Thresher CLI.

All terminal output formatting and ASCII art lives here.
Pure Python — no external dependencies, just ANSI escape sequences.
"""

from __future__ import annotations

import sys
import threading

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
    print(f"  Report: {ARCTIC}{path}/report.html{RESET}")
    print()


def print_swim_divider() -> None:
    """Print the ~~~_/|~~~ divider in violet."""
    print(f"  {VIOLET}~~~~~~~~~~~_/|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{RESET}")
    print()


class FinSpinner:
    """Animated shark fin spinner for long-running operations.

    Usage:
        with FinSpinner("Building VM"):
            do_long_operation()
        # Automatically shows [OK] when done, [!!] on exception
    """

    _FRAMES = ["_/|", "_//", "__/", "\\__", "\\_/", "/\\_", "|/_", "|\\_"]

    def __init__(self, label: str) -> None:
        self.label = label
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._failed = False

    def __enter__(self) -> "FinSpinner":
        self._stop_event.clear()
        self._failed = False
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._failed = exc_type is not None
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
        # Clear the spinner line and print final status
        sys.stdout.write(f"\r\033[K")
        sys.stdout.flush()
        if self._failed:
            print_stage_fail(self.label)
        else:
            print_stage_ok(self.label)
        return None  # don't suppress exceptions

    def _animate(self) -> None:
        i = 0
        while not self._stop_event.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            sys.stdout.write(
                f"\r  {VIOLET}{frame}{RESET} {GRAY}{self.label}{RESET}  "
            )
            sys.stdout.flush()
            i += 1
            self._stop_event.wait(0.12)


class FinProgressBar:
    """Animated shark fin progress bar for staged operations.

    Usage:
        bar = FinProgressBar("Provisioning", total=25)
        bar.update(1, "Installing Git")
        bar.update(2, "Installing Docker")
        ...
        bar.finish()
    """

    def __init__(self, label: str, total: int, width: int = 40) -> None:
        self.label = label
        self.total = total
        self.width = width
        self._current = 0
        self._status = ""

    def update(self, current: int, status: str = "") -> None:
        """Update progress bar to current step."""
        self._current = min(current, self.total)
        self._status = status
        self._draw()

    def _draw(self) -> None:
        pct = self._current / self.total if self.total > 0 else 0
        filled = int(self.width * pct)
        fin = "_/|"

        if filled < self.width - 3:
            bar = "=" * filled + fin + " " * (self.width - filled - 3)
        else:
            bar = "=" * self.width

        pct_str = f"{int(pct * 100)}%"
        status = self._status[:30] if self._status else ""

        sys.stdout.write(
            f"\r  {GRAY}{self.label} [{VIOLET}{bar}{GRAY}] "
            f"{WHITE}{pct_str}{RESET} {DIM}{status}{RESET}\033[K"
        )
        sys.stdout.flush()

    def finish(self) -> None:
        """Complete the progress bar."""
        self._current = self.total
        filled = "=" * self.width
        sys.stdout.write(
            f"\r  {GRAY}{self.label} [{GREEN}{filled}{GRAY}] "
            f"{GREEN}done{RESET}\033[K\n"
        )
        sys.stdout.flush()


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
