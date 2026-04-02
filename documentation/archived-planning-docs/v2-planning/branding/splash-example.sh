#!/bin/bash
# splash-example.sh — Example of Thresher CLI splash screen
# Run this to preview the branding in your terminal.

# Colors
RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
BLUE='\033[38;5;117m'
RED='\033[38;5;203m'
GREEN='\033[38;5;114m'
AMBER='\033[38;5;214m'
WHITE='\033[38;5;255m'
GRAY='\033[38;5;245m'

clear

# Shark splash
echo -e "${BLUE}"
cat << 'SHARK'
                                          ___/|
                              ___________/    |
                   __________/                |
               ___/    _____                  |
           ___/   \___/     \                 |
       ___/                  \         ______/
   ___/         _              \______/
  /          __/ \__    ___----~
 |      ,__-~      \--~
SHARK
echo -en "${RESET}"

echo -e " |     /    _,                  ${BOLD}${WHITE}T H R E S H E R${RESET}"
echo -e "${BLUE}  \\___/  __/${RESET}"
echo -e "${BLUE}     |  /${RESET}                       ${DIM}Separate the safe${RESET}"
echo -e "${BLUE}     |_/${RESET}                        ${DIM}from the dangerous.${RESET}"
echo -e "${BLUE}      ~${RESET}"
echo ""
echo -e "                                    ${GRAY}thresher.sh | v2.0.0${RESET}"
echo ""
echo -e "  ${GRAY}────────────────────────────────────────────────────────${RESET}"
echo ""

# Simulated scan
REPO="https://github.com/example/repo"
echo -e "  Scanning: ${BLUE}${REPO}${RESET}"
echo -e "  Target:   ${WHITE}example/repo${RESET} ${GRAY}(main)${RESET}"
echo ""

# Progress simulation
steps=(
  "Cloning repository (hardened)"
  "Resolving dependencies"
  "Running vulnerability scanners"
  "Running static analysis"
  "Running supply chain analysis"
  "Running malware detection"
)

for i in "${!steps[@]}"; do
  step_num=$((i + 1))
  echo -ne "  ${GRAY}[${step_num}/7]${RESET} ${steps[$i]}..."
  sleep 0.4
  echo -e " ${GREEN}done${RESET}"
done

# AI analysts with swimming fin
echo -e "  ${GRAY}[7/7]${RESET} AI analyst panel (8 analysts)"
echo ""

analysts=(
  "The Paranoid"
  "The Behaviorist"
  "The Investigator"
  "Pentester: Vulns"
  "Pentester: App Surface"
  "Pentester: Memory"
  "Infra Auditor"
  "The Shadowcatcher"
)

for i in "${!analysts[@]}"; do
  num=$((i + 1))
  echo -ne "         ${BLUE}${num}.${RESET} ${analysts[$i]}"
  # Pad to column
  padding=$((32 - ${#analysts[$i]}))
  printf '%*s' "$padding" ''
  sleep 0.3
  echo -e "${GREEN}done${RESET}"
done

echo ""
echo -e "  ${GRAY}────────────────────────────────────────────────────────${RESET}"
echo ""

# Results
echo -e "  ${BOLD}${WHITE}FINDINGS${RESET}"
echo ""
echo -e "  ${RED}P0${RESET}  ${RED}CRIT${RESET}  ${AMBER}HIGH${RESET}  ${AMBER}MED${RESET}   ${GRAY}LOW${RESET}"
echo -e "   0     2      5     12    23"
echo ""

# Top findings
echo -e "  ${RED}[CRITICAL]${RESET} CVE-2026-1234 in ${WHITE}lodash@4.17.20${RESET}"
echo -e "             EPSS: 0.94 | In CISA KEV"
echo -e "             Fix: upgrade to ${GREEN}4.17.21${RESET}"
echo ""
echo -e "  ${RED}[CRITICAL]${RESET} Suspicious install script in ${WHITE}left-pad@2.0.0${RESET}"
echo -e "             postinstall downloads from external URL"
echo -e "             Flagged by: ${BLUE}Paranoid${RESET}, ${BLUE}Shadowcatcher${RESET}"
echo ""
echo -e "  ${AMBER}[HIGH]${RESET}     Maintainer changed on ${WHITE}colors@1.5.0${RESET}"
echo -e "             New publisher: ghost account, 0 other packages"
echo -e "             Flagged by: ${BLUE}Investigator${RESET}"
echo ""
echo -e "  ${GRAY}────────────────────────────────────────────────────────${RESET}"
echo ""
echo -e "  Report: ${BLUE}./thresher-reports/example-repo-20260401/${RESET}"
echo ""

# Swimming divider
echo -e "  ${BLUE}~~~~~~~~~~~_/|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${RESET}"
echo ""
