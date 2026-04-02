#!/bin/bash
# loading-animations.sh — Animated shark fin loading indicators
# Run this to preview all animation styles.

RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
VIOLET='\033[38;5;141m'
ARCTIC='\033[38;5;195m'
GRAY='\033[38;5;245m'
GREEN='\033[38;5;114m'
WHITE='\033[38;5;255m'
# Hide cursor
HIDE='\033[?25l'
SHOW='\033[?25h'

# Restore cursor on exit
trap "echo -en '${SHOW}'" EXIT

clear

echo -e "${ARCTIC}${BOLD}Thresher Loading Animations${RESET}"
echo -e "${GRAY}Press Ctrl+C to skip to next animation${RESET}"
echo ""

# ═══════════════════════════════════════════════════════════
# 1. Swimming Divider — fin goes back and forth
# ═══════════════════════════════════════════════════════════

echo -e "${ARCTIC}${BOLD}1. Swimming Divider${RESET}"
echo -e "${GRAY}Fin swims back and forth across a water line${RESET}"
echo ""

swim_divider() {
    local width=56
    local fin="_/|"
    local fin_len=${#fin}
    local cycles=${1:-3}
    local delay=0.04

    echo -en "${HIDE}"

    for ((cycle=0; cycle<cycles; cycle++)); do
        # Swim right
        for ((pos=0; pos<=width-fin_len; pos++)); do
            local left_water=""
            local right_water=""
            for ((i=0; i<pos; i++)); do left_water+="~"; done
            for ((i=pos+fin_len; i<width; i++)); do right_water+="~"; done
            echo -en "\r  ${GRAY}${left_water}${VIOLET}${fin}${GRAY}${right_water}${RESET}"
            sleep $delay
        done
        # Swim left (flip the fin)
        local fin_rev="|\\_"
        for ((pos=width-fin_len; pos>=0; pos--)); do
            local left_water=""
            local right_water=""
            for ((i=0; i<pos; i++)); do left_water+="~"; done
            for ((i=pos+fin_len; i<width; i++)); do right_water+="~"; done
            echo -en "\r  ${GRAY}${left_water}${VIOLET}${fin_rev}${GRAY}${right_water}${RESET}"
            sleep $delay
        done
    done

    echo -en "${SHOW}"
    echo ""
}

swim_divider 2
echo ""
sleep 1

# ═══════════════════════════════════════════════════════════
# 2. Progress Bar — fin swims across a loading bar
# ═══════════════════════════════════════════════════════════

echo -e "${ARCTIC}${BOLD}2. Progress Bar with Shark Fin${RESET}"
echo -e "${GRAY}Fin fills a progress bar left to right${RESET}"
echo ""

shark_progress() {
    local label="$1"
    local width=40
    local fin="_/|"
    local fin_len=${#fin}
    local delay=0.03

    echo -en "${HIDE}"

    for ((pos=0; pos<=width; pos++)); do
        local filled=""
        local empty=""
        local pct=$((pos * 100 / width))

        # Build the bar
        for ((i=0; i<pos && i<width-fin_len; i++)); do filled+="="; done

        # Position the fin at the leading edge
        local bar=""
        if ((pos < width - fin_len)); then
            for ((i=pos+fin_len; i<width; i++)); do empty+=" "; done
            bar="${filled}${fin}${empty}"
        else
            for ((i=0; i<width; i++)); do filled+="="; done
            bar="${filled:0:$width}"
        fi

        echo -en "\r  ${GRAY}${label} [${VIOLET}${bar}${GRAY}] ${WHITE}${pct}%%${RESET}"
        sleep $delay
    done

    echo -en "\r  ${GRAY}${label} [${GREEN}"
    for ((i=0; i<width; i++)); do echo -en "="; done
    echo -en "${GRAY}] ${GREEN}done${RESET}"

    echo -en "${SHOW}"
    echo ""
}

shark_progress "Scanning   "
sleep 0.3
shark_progress "Analyzing  "
sleep 0.3
shark_progress "Reporting  "
echo ""
sleep 1

# ═══════════════════════════════════════════════════════════
# 3. Compact Spinner — tiny fin rotates
# ═══════════════════════════════════════════════════════════

echo -e "${ARCTIC}${BOLD}3. Fin Spinner${RESET}"
echo -e "${GRAY}Rotating fin for inline status${RESET}"
echo ""

fin_spinner() {
    local label="$1"
    local duration=${2:-3}
    local frames=("_/|" "_//" "__/" "\\__" "\\/_" "/\\_" "|/_" "|\\_ " )
    local frame_count=${#frames[@]}
    local delay=0.12
    local iterations=$((duration * 8))

    echo -en "${HIDE}"

    for ((i=0; i<iterations; i++)); do
        local frame_idx=$((i % frame_count))
        echo -en "\r  ${VIOLET}${frames[$frame_idx]}${RESET} ${GRAY}${label}${RESET}  "
        sleep $delay
    done

    echo -en "\r  ${GREEN} ok${RESET} ${GRAY}${label}${RESET}  "
    echo -en "${SHOW}"
    echo ""
}

fin_spinner "Running vulnerability scanners..." 2
fin_spinner "Running static analysis..." 2
fin_spinner "Running supply chain analysis..." 2
echo ""
sleep 1

# ═══════════════════════════════════════════════════════════
# 4. Multi-line swimming shark (bigger animation)
# ═══════════════════════════════════════════════════════════

echo -e "${ARCTIC}${BOLD}4. Swimming Shark (Multi-line)${RESET}"
echo -e "${GRAY}Full shark profile swims across${RESET}"
echo ""

swimming_shark() {
    local width=60
    local cycles=${1:-1}
    local delay=0.05

    # Shark frames (3 lines tall)
    local line1="   _/|"
    local line2="_____/ /"
    local line3="/ _  __/"
    local line4="|/-~~"

    local shark_width=8
    local water="~"

    echo -en "${HIDE}"
    # Reserve 4 lines
    echo ""; echo ""; echo ""; echo ""
    echo -en "\033[4A"

    for ((cycle=0; cycle<cycles; cycle++)); do
        for ((pos=0; pos<=width-shark_width; pos++)); do
            # Build padding
            local pad=""
            for ((i=0; i<pos; i++)); do pad+=" "; done

            # Build water
            local water_line=""
            for ((i=0; i<width+4; i++)); do water_line+="~"; done

            # Move cursor up 4 lines and redraw
            echo -en "\033[4A"
            echo -e "\r  ${pad}${VIOLET}   _/|${RESET}                    "
            echo -e "\r  ${pad}${VIOLET}_____/ /${RESET}                  "
            echo -e "\r  ${pad}${VIOLET}/ _  __/${RESET}                  "
            echo -e "\r  ${GRAY}${water_line}${RESET}"

            sleep $delay
        done

        # Swim back (flipped)
        for ((pos=width-shark_width; pos>=0; pos--)); do
            local pad=""
            for ((i=0; i<pos; i++)); do pad+=" "; done

            local water_line=""
            for ((i=0; i<width+4; i++)); do water_line+="~"; done

            echo -en "\033[4A"
            echo -e "\r  ${pad}${VIOLET}|\\_   ${RESET}                   "
            echo -e "\r  ${pad}${VIOLET}\\ \\_____${RESET}               "
            echo -e "\r  ${pad}${VIOLET}\\__  _ \\${RESET}               "
            echo -e "\r  ${GRAY}${water_line}${RESET}"

            sleep $delay
        done
    done

    echo -en "${SHOW}"
    echo ""
}

swimming_shark 1
sleep 1

# ═══════════════════════════════════════════════════════════
# 5. Full scan simulation
# ═══════════════════════════════════════════════════════════

echo ""
echo -e "${ARCTIC}${BOLD}5. Full Scan Simulation${RESET}"
echo -e "${GRAY}Putting it all together${RESET}"
echo ""
sleep 1

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
echo -e "${VIOLET}     |  /${RESET}                       ${DIM}v2.0.0 | thresher.sh${RESET}"
echo -e "${VIOLET}     |_/${RESET}"
echo -e "${VIOLET}      ~${RESET}"
echo ""
echo -e "  Scanning: ${ARCTIC}https://github.com/example/repo${RESET}"
echo ""

# Phase progress bars
shark_progress "Clone      "
sleep 0.2
shark_progress "Deps       "
sleep 0.2
shark_progress "Vuln scan  "
sleep 0.2
shark_progress "SAST       "
sleep 0.2
shark_progress "Supply ch. "
sleep 0.2
shark_progress "Malware    "
echo ""

# AI analysts with spinner
echo -e "  ${ARCTIC}${BOLD}AI Analyst Panel${RESET}"
echo ""
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
  fin_spinner "Analyst ${num}: ${analysts[$i]}" 1
done

echo ""

# Swimming divider before results
swim_divider 1

echo ""
echo -e "  ${BOLD}${ARCTIC}FINDINGS${RESET}"
echo ""
echo -e "  ${BOLD}\033[38;5;203mP0${RESET}  ${BOLD}\033[38;5;203mCRIT${RESET}  ${BOLD}\033[38;5;214mHIGH${RESET}  ${BOLD}\033[38;5;214mMED${RESET}   ${GRAY}LOW${RESET}"
echo -e "   0     2      5     12    23"
echo ""
echo -e "  Report: ${ARCTIC}./thresher-reports/example-repo-20260401/${RESET}"
echo ""
echo -e "  ${VIOLET}~~~~~~~~~~~_/|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${RESET}"
echo ""
