#!/usr/bin/env bash
# Copies repo-sentinel into a target repository. Never overwrites existing files.
#
# Usage: ./install.sh <target-repo> [--with-ci]
#   --with-ci   also adds .github/workflows/security.yml
set -euo pipefail

KIT="$(cd "$(dirname "$0")" && pwd)/template"
TARGET="${1:?Usage: ./install.sh <target-repo> [--with-ci]}"
WITH_CI=false
[[ "${2:-}" == --with-ci ]] && WITH_CI=true

TARGET="$(git -C "$TARGET" rev-parse --show-toplevel)" || { echo "Not a git repository: $1" >&2; exit 1; }

FILES=(
  lefthook.yml
  .security/config.env
  scripts/security/security.sh
  .gitleaks.toml
  osv-scanner.toml
  .trivyignore.yaml
)
$WITH_CI && FILES+=(.github/workflows/security.yml)

for f in "${FILES[@]}"; do
  if [[ -e "$TARGET/$f" ]]; then
    echo "skipped (already exists, merge by hand): $f"
  else
    mkdir -p "$(dirname "$TARGET/$f")"
    cp "$KIT/$f" "$TARGET/$f"
    echo "added: $f"
  fi
done
chmod +x "$TARGET/scripts/security/security.sh"

# With core.autocrlf=true on Windows the scripts are checked out with CRLF and bash fails.
ATTR="$TARGET/.gitattributes"
if ! grep -qs 'scripts/security/\*\.sh' "$ATTR"; then
  printf '\n# repo-sentinel: bash files must stay LF on every platform\nscripts/security/*.sh text eol=lf\n.security/config.env text eol=lf\n' >>"$ATTR"
  echo "updated: .gitattributes (eol=lf)"
fi

echo
if command -v lefthook >/dev/null 2>&1; then
  (cd "$TARGET" && lefthook install)
else
  echo "lefthook not found. Install it and run 'lefthook install' in the target repo:"
  echo "  Windows: winget install evilmartians.lefthook   macOS: brew install lefthook   Node: npm i -D lefthook"
fi

cat <<EOT

Next steps (in the target repo):
  bash scripts/security/security.sh pull     # download the images once (~1 GB)
  bash scripts/security/security.sh doctor   # verify the environment
  bash scripts/security/security.sh scan     # full scan of the current state
EOT
