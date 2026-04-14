#!/bin/bash

# ==========================================
# AI-Driven säkerhetsautomation
# Identifierar potentiellt osäkra filer
# ==========================================

# -------- Inställningar --------
RISK_EXTENSIONS=("sh" "exe" "bat" "ps1" "jar" "js")
SUSPICIOUS_WORDS=("password" "secret" "backup" "hack" "token" "key")
MAX_SIZE=$((5 * 1024 * 1024))   # 5 MB
RECENT_DAYS=7

# -------- Funktioner --------
print_usage() {
    echo "Användning: $0 <katalog>"
}

directory_exists() {
    local dir="$1"
    [[ -d "$dir" ]]
}

is_regular_file() {
    local file="$1"
    [[ -f "$file" ]]
}

has_risky_extension() {
    local filename="$1"
    local extension="${filename##*.}"

    # Om filen inte har någon punkt, undvik falsk träff
    [[ "$filename" == *.* ]] || return 1

    for ext in "${RISK_EXTENSIONS[@]}"; do
        if [[ "$extension" == "$ext" ]]; then
            return 0
        fi
    done
    return 1
}

contains_suspicious_word() {
    local filename_lower="$1"
    for word in "${SUSPICIOUS_WORDS[@]}"; do
        if [[ "$filename_lower" == *"$word"* ]]; then
            echo "$word"
            return 0
        fi
    done
    return 1
}

is_large_file() {
    local size="$1"
    [[ "$size" -gt "$MAX_SIZE" ]]
}

is_recently_modified() {
    local modified="$1"
    local now
    now=$(date +%s)

    local age_days=$(( (now - modified) / 86400 ))
    [[ "$age_days" -le "$RECENT_DAYS" ]]
}

# -------- Start --------
if [[ $# -ne 1 ]]; then
    print_usage
    exit 1
fi

DIR="$1"

if ! directory_exists "$DIR"; then
    echo "Fel: katalogen finns inte: $DIR"
    exit 1
fi

echo "Analyserar katalog: $DIR"
echo "----------------------------------------"

files_checked=0
files_flagged=0
found_any=0

for file in "$DIR"/*; do
    [[ -e "$file" ]] || continue

    if is_regular_file "$file"; then
        found_any=1
        ((files_checked++))

        filename=$(basename "$file")

        # Hämta filinfo
        if ! size=$(stat -c%s "$file" 2>/dev/null); then
            echo "Kunde inte läsa storlek för: $filename"
            continue
        fi

        if ! modified=$(stat -c%Y "$file" 2>/dev/null); then
            echo "Kunde inte läsa ändringstid för: $filename"
            continue
        fi

        warnings=()

        # Kontroll 1: riskfylld filändelse
        if has_risky_extension "$filename"; then
            warnings+=("Riskfylld filändelse")
        fi

        # Kontroll 2: stor fil
        if is_large_file "$size"; then
            warnings+=("Stor fil (${size} byte)")
        fi

        # Kontroll 3: nyligen ändrad
        if is_recently_modified "$modified"; then
            age_days=$(( ($(date +%s) - modified) / 86400 ))
            warnings+=("Nyligen ändrad (${age_days} dagar sedan)")
        fi

        # Kontroll 4: misstänkt filnamn
        lower_name=$(echo "$filename" | tr '[:upper:]' '[:lower:]')
        suspicious_word=$(contains_suspicious_word "$lower_name")
        if [[ -n "$suspicious_word" ]]; then
            warnings+=("Misstänkt ord i filnamn: $suspicious_word")
        fi

        # Extra kontroll: dold fil
        if [[ "$filename" == .* ]]; then
            warnings+=("Dold fil")
        fi

        # Skriv resultat
        if [[ ${#warnings[@]} -gt 0 ]]; then
            ((files_flagged++))
            echo "Fil: $filename"
            for warning in "${warnings[@]}"; do
                echo "  - $warning"
            done
            echo
        fi
    fi
done

if [[ "$found_any" -eq 0 ]]; then
    echo "Katalogen innehåller inga vanliga filer."
    exit 0
fi

echo "----------------------------------------"
echo "Sammanfattning:"
echo "Kontrollerade filer: $files_checked"
echo "Filer med avvikelser: $files_flagged"