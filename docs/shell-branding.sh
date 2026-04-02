#!/bin/bash
# shell-branding.sh — Thresher shell branding demo
# Run: bash site/shell-branding.sh

RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
VIOLET='\033[38;5;141m'
ARCTIC='\033[38;5;195m'
GRAY='\033[38;5;245m'
GREEN='\033[38;5;114m'
RED='\033[38;5;203m'
AMBER='\033[38;5;214m'
WHITE='\033[38;5;255m'
HIDE='\033[?25l'
SHOW='\033[?25h'

trap "echo -en '${SHOW}'" EXIT

clear

# ═══════════════════════════════════════════════════════════
# Full scan simulation
# ═══════════════════════════════════════════════════════════

# Splash
echo -e "${VIOLET}                                          ___/|${RESET}"
echo -e "${VIOLET}                              ___________/    |${RESET}"
echo -e "${VIOLET}                   __________/                |${RESET}"
echo -e "${VIOLET}               ___/    _____                  |${RESET}"
echo -e "${VIOLET}           ___/   \\___/     \\                 |${RESET}"
echo -e "${VIOLET}       ___/                  \\         ______/${RESET}"
echo -e "${VIOLET}   ___/         _              \\______/${RESET}"
echo -e "${VIOLET}  /          __/ \\__    ___----~${RESET}"
echo -e "${VIOLET} |      ,__-~      \\--~${RESET}"
echo -e " |     /    _,                  ${BOLD}${ARCTIC}T H R E S H E R${RESET}"
echo -e "${VIOLET}  \\___/  __/${RESET}"
echo -e "${VIOLET}     |  /${RESET}                       ${DIM}v0.2.0 | thresher.sh${RESET}"
echo -e "${VIOLET}     |_/${RESET}"
echo -e "${VIOLET}      ~${RESET}"
echo ""
echo -e "  Scanning: ${ARCTIC}https://github.com/example/repo${RESET}"
echo ""

sleep 0.5

# Stage completions
stages=(
  "Cloning repository (hardened)"
  "Discovering hidden dependencies"
  "Resolving dependencies (3 ecosystems)"
  "Vulnerability scanners (22 tools)"
  "AI analyst panel"
)

for stage in "${stages[@]}"; do
  sleep 0.4
  echo -e "  ${GREEN}[OK]${RESET} ${stage}"
done

echo ""

# AI analysts
analysts=(
  "The Paranoid"
  "The Behaviorist"
  "The Investigator"
  "Vuln Pentester"
  "App Pentester"
  "Memory Exploiter"
  "Infra Auditor"
  "The Shadowcatcher"
)

for i in "${!analysts[@]}"; do
  num=$((i + 1))
  name="${analysts[$i]}"
  # Pad with dots
  label="Analyst ${num}: ${name} "
  target_len=40
  current_len=${#label}
  dots_needed=$((target_len - current_len))
  dots=""
  for ((d=0; d<dots_needed; d++)); do dots+="."; done
  sleep 0.3
  echo -e "    ${GRAY}${label}${dots}${RESET} ${GREEN}done${RESET}"
done

echo ""
sleep 0.3
echo -e "  ${GREEN}[OK]${RESET} Adversarial verification"
sleep 0.3
echo -e "  ${GREEN}[OK]${RESET} Report synthesis"
echo ""

# Swimming divider
echo -e "  ${VIOLET}~~~~~~~~~~~_/|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${RESET}"
echo ""

# Findings
echo -e "  ${BOLD}${ARCTIC}FINDINGS${RESET}"
echo ""
echo -e "  ${BOLD}${RED}P0${RESET}  ${BOLD}${RED}CRIT${RESET}  ${BOLD}${AMBER}HIGH${RESET}  ${BOLD}${AMBER}MED${RESET}   ${GRAY}LOW${RESET}"
echo -e "   0     2      5     12    23"
echo ""
echo -e "  Report: ${ARCTIC}./thresher-reports/example-repo-20260401/${RESET}"
echo ""
echo -e "  ${VIOLET}~~~~~~~~~~~_/|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${RESET}"
echo ""
