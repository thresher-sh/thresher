# Thresher Branding

## Name

**Thresher** — a supply chain security scanner that separates the safe from the dangerous.

The name works on three levels:
- **Threshing machine** — separates grain from chaff. The tool separates safe code from threats.
- **Thresher shark** — fast, distinctive, relentless. The whip-like tail is the visual identity.
- **thresher.sh** — the domain is the install command. Shell-native.

## Tagline

Primary: **Separate the safe from the dangerous.**

Alternates:
- "Supply chain security, teeth included."
- "What's hiding in your dependencies?"
- "8 eyes. Every angle. Nothing hides."

## Domain & Install

- **Website**: `https://thresher.sh`
- **GitHub**: `https://github.com/shadowcodex/thresher`
- **Install command**: `curl -fsSL thresher.sh/install | bash`

The domain-as-installer pattern (like `rustup.rs`, `bun.sh`) makes the install command memorable and brandable. The `/install` endpoint serves a shell script that detects OS/arch and installs the appropriate binary/package.

## Visual Identity

### Mascot: The Thresher Shark

The thresher shark (Alopias) is instantly recognizable by its elongated upper tail fin, which can be as long as its body. It uses the tail like a whip to stun prey. Visual metaphor: precision strike, nothing escapes.

**Design direction**:
- Minimal silhouette — the tail is the signature element
- Works at 16x16 favicon size (just the fin/tail curve)
- Works as ASCII art in terminal output
- No cartoon/cute — this is a security tool, keep it sharp

### Color Palette

Dark-themed, terminal-native. The brand should feel like it belongs in a terminal window.

| Name | Hex | Usage |
|------|-----|-------|
| **Deep Black** | `#0a0a0a` | Primary background |
| **Terminal Black** | `#1a1a1a` | Card/surface background |
| **Charcoal** | `#2a2a2a` | Borders, dividers |
| **Steel** | `#6b7280` | Secondary text, muted elements |
| **Bone** | `#e5e5e5` | Primary text |
| **Arctic White** | `#f0f9ff` | Primary accent — headings, wordmark, links, text highlights. Nearly invisible as a "color" but crisp against black. |
| **Vapor Violet** | `#a78bfa` | Secondary accent — the shark, section labels, analyst numbers, install box border, swimming divider, hover glows. The rare pop of color. |
| **Threat Red** | `#ef4444` | Critical findings, warnings |
| **Safe Green** | `#22c55e` | Clean/pass indicators |
| **Amber** | `#f59e0b` | Medium severity, caution |

**Rule**: The brand is near-monochrome. Arctic White is the primary voice — clean, sharp, almost colorless. Vapor Violet is the signature — used sparingly on the shark, interactive elements, and highlights. The page is black and white until the violet hits. Red/green/amber are functional only (findings severity), never decorative.

### Typography

**Terminal/Console** (CLI output, website code blocks, the primary brand voice):
- `JetBrains Mono` — primary monospace. Clean, distinctive, great ligatures.
- Fallback: `Fira Code`, `Cascadia Code`, `monospace`

**Web headings**:
- `Inter` — clean sans-serif, pairs well with monospace
- Weights: 700 for headings, 400 for body

**Rule**: The website should feel like a terminal that grew a landing page. Monospace is the dominant typeface. Sans-serif is secondary.

### Logo Variants

1. **Wordmark**: `thresher` in JetBrains Mono, weight 700, shark blue on black. The `t` or the `h` could subtly incorporate the tail curve.

2. **Icon**: Thresher shark silhouette — side profile showing the elongated tail. Single color (white on black, or shark blue on black). Must work at:
   - 512x512 (README, social)
   - 128x128 (website nav)
   - 32x32 (favicon)
   - 16x16 (terminal icon)

3. **Favicon**: Just the tail curve — a single swooping line. Recognizable at pixel scale.

4. **ASCII mark**: Used in CLI splash screen and report headers. Multiple sizes (see ASCII Art section).

## ASCII Art

### Full Splash (shown on `thresher scan` startup)

```
        ___
       /   \___
      /         \__
     /    ()        \___
    /                   \____
   /  ___                    \__________
  /  /   \                              \
 /  /     \    T H R E S H E R          /
|  |       |   ~~~~~~~~~~~~~~~~~~~~~~~~/
 \  \     /   Separate the safe from  /
  \  \___/    the dangerous.         /
   \                         _______/
    \                _______/
     \        ______/
      \______/
```

### Compact (report headers, narrow terminals)

```
    /\___
   /  () \___
  /          \____
 | THRESHER      /
  \      _______/
   \____/
```

### Minimal Fin (progress indicator, inline)

```
  /\
 /  \___
/______/
```

### Scan Progress Animation Frames

```
Frame 1:    ~~/\~~
Frame 2:   ~~/ \~~
Frame 3:  ~~/   \~~
Frame 4:   ~~\ /~~
Frame 5:    ~~\/~~
```

## CLI Output Style

### Scan Startup

```
        ___
       /   \___
      /         \__
     /    ()        \___
    /                   \____
   /  ___                    \__________
  /  /   \                              \
 /  /     \    T H R E S H E R          /
|  |       |   ~~~~~~~~~~~~~~~~~~~~~~~~/
 \  \     /   v2.0.0                  /
  \  \___/    thresher.sh            /
   \                         _______/
    \                _______/
     \        ______/
      \______/

  Scanning: https://github.com/example/repo
  Target:   example/repo (main)

  [1/7] Cloning repository (hardened)........... done
  [2/7] Resolving dependencies.................. done
  [3/7] Running vulnerability scanners.......... done
  [4/7] Running static analysis................. done
  [5/7] Running supply chain analysis........... done
  [6/7] Running malware detection............... done
  [7/7] AI analyst panel (8 analysts)........... running

     /\     Analyst 1: The Paranoid ............. done
    /  \    Analyst 2: The Behaviorist .......... done
   /    \   Analyst 3: The Investigator ......... done
  /      \  Analyst 4: Pentester: Vulns ......... done
 /   ()   \ Analyst 5: Pentester: App Surface ... running
 \        / Analyst 6: Pentester: Memory ........ done
  \      /  Analyst 7: Infra Auditor ............ done
   \    /   Analyst 8: The Shadowcatcher ........ done
    \__/

  Synthesizing report...
```

### Scan Complete

```
  ============================================================
    /\___
   /  () \___       THRESHER SECURITY REPORT
  /          \____  example/repo @ main
 | 2026-04-01     /  v2.0.0
  \      _______/
   \____/
  ============================================================

  FINDINGS SUMMARY

  P0  Critical  High  Medium  Low
   0     2        5      12    23

  TOP RISKS
  ----
  [CRITICAL] CVE-2026-1234 in lodash@4.17.20
             EPSS: 0.94 | In CISA KEV | Fix: upgrade to 4.17.21
  [CRITICAL] Suspicious install script in left-pad@2.0.0
             postinstall downloads from external URL
  ...

  Full report: ./thresher-reports/example-repo-20260401-143022/

  ============================================================
```

## Website Design Direction

### Principles

1. **Terminal-first aesthetic** — the website should look like a beautifully styled terminal. Dark background, monospace type, cursor blinks, scan output animations.
2. **Black on white? No — white on black.** The brand is dark mode native. Light mode is the afterthought, not the default.
3. **Single accent color** — shark blue (`#38bdf8`) is the only color beyond the grayscale. It draws the eye to CTAs, links, and the shark.
4. **Content is code** — examples, install commands, and scan output are the hero content. No stock photos, no abstract illustrations. The product speaks for itself.
5. **Console aesthetic** — borders use box-drawing characters or simple lines. Cards have subtle terminal-style borders. Buttons look like CLI prompts.

### Landing Page Structure

1. **Hero**: Full splash ASCII shark + tagline + install command (copyable)
2. **What it does**: Three-column grid — "16 Scanners", "8 AI Analysts", "VM Isolated"
3. **How it works**: Animated terminal showing a scan running in real-time
4. **Watch Zones**: Visual of the 10 zones with coverage indicators
5. **Install**: The one-liner, OS detection, package manager alternatives
6. **Footer**: GitHub link, docs link, license

### Brand Voice

- **Direct** — no marketing fluff. "Thresher scans your dependencies for threats." Not "Thresher empowers developers to proactively manage supply chain risk."
- **Technical** — assume the reader knows what a CVE is, what npm is, what a supply chain attack looks like.
- **Confident** — "8 analysts. Every angle. Nothing hides." Not "helps find potential issues."
- **Terse** — short sentences. Active voice. Terminal-like.

## File Naming Convention

- `thresher` — the CLI binary
- `thresher.sh` — the website domain
- `thresher-reports/` — output directory
- `thresher.toml` — config file
- `.thresher/` — local cache/state directory
