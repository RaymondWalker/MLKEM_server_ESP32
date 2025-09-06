#!/usr/bin/env bash
# Remove stray crypto_kem_* compile definitions from the MLKEM component CMake
# Usage: ./fix-mlkem-defs.sh [path/to/CMakeLists.txt]
set -euo pipefail

FILE="${1:-components/mlkem/CMakeLists.txt}"

if [[ ! -f "$FILE" ]]; then
  echo "ERROR: Can't find $FILE" >&2
  exit 1
fi

ts="$(date +%Y%m%d-%H%M%S)"
bak="${FILE}.bak.${ts}"
cp -a "$FILE" "$bak"

# Strip any occurrences whether they are alone on a line or inside a
# target_compile_definitions/add_compile_definitions(...) block.
sed -i -E '
  s/[[:space:]]*crypto_kem_keypair[[:space:]]*=[[:space:]]*[A-Za-z0-9_]+//g;
  s/[[:space:]]*crypto_kem_enc[[:space:]]*=[[:space:]]*[A-Za-z0-9_]+//g;
  s/[[:space:]]*crypto_kem_dec[[:space:]]*=[[:space:]]*[A-Za-z0-9_]+//g;
  # squeeze extra spaces left behind
  s/[[:space:]]{2,}/ /g;
  # drop empty lines left behind
  /^\s*$/d
' "$FILE"

echo "Cleaned: $FILE"
echo "Backup  : $bak"
echo

# Show what (if anything) is left to remove
if grep -nE 'crypto_kem_(keypair|enc|dec)=' "$FILE" >/dev/null; then
  echo "NOTE: some matches still remain in $FILE:"
  grep -nE 'crypto_kem_(keypair|enc|dec)=' "$FILE" || true
else
  echo "OK: no crypto_kem_* definitions remain in $FILE"
fi

echo
echo "Next steps:"
echo "  idf.py fullclean && idf.py build"
