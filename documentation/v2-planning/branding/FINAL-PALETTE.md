# Thresher — Final Color Palette

## Dual Accent: Arctic White + Vapor Violet

| Role | Name | Hex | Where |
|------|------|-----|-------|
| Background | Deep Black | `#0a0a0a` | Page background |
| Surface | Terminal Black | `#1a1a1a` | Cards, code blocks, terminal body |
| Border | Charcoal | `#2a2a2a` | Dividers, card borders |
| Muted | Steel | `#6b7280` | Secondary text, timestamps, labels |
| Body | Bone | `#e5e5e5` | Body text |
| **Primary accent** | **Arctic White** | **`#f0f9ff`** | Wordmark, headings, links, CLI highlights, package names |
| **Signature accent** | **Vapor Violet** | **`#a78bfa`** | The shark, section titles, analyst numbers, install border, swimming divider, hover glow |
| Severity | Threat Red | `#ef4444` | Critical/P0 findings |
| Severity | Amber | `#f59e0b` | High/Medium findings |
| Severity | Safe Green | `#22c55e` | Pass/clean/done indicators |

## CSS Variables

```css
:root {
  --deep-black: #0a0a0a;
  --terminal-black: #1a1a1a;
  --charcoal: #2a2a2a;
  --steel: #6b7280;
  --bone: #e5e5e5;
  --arctic: #f0f9ff;
  --violet: #a78bfa;
  --violet-dim: rgba(167, 139, 250, 0.15);
  --violet-glow: rgba(167, 139, 250, 0.08);
  --threat-red: #ef4444;
  --safe-green: #22c55e;
  --amber: #f59e0b;
}
```

## ANSI Terminal Colors

```bash
ARCTIC='\033[38;5;195m'
VIOLET='\033[38;5;141m'
WHITE='\033[38;5;255m'
GRAY='\033[38;5;245m'
RED='\033[38;5;203m'
GREEN='\033[38;5;114m'
AMBER='\033[38;5;214m'
```
