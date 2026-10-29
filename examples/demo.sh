#!/bin/sh
# End-to-end tour of pm against a throwaway vault.
# Usage: sh examples/demo.sh   (run from the repo root)
set -e
cd "$(dirname "$0")/.."

zig build

DEMO_DIR="$(mktemp -d)"
trap 'rm -rf "$DEMO_DIR"' EXIT INT TERM
export PM_VAULT="$DEMO_DIR/vault.pm"
export PM_MASTER_PASSWORD="demo-master-password"

PM=./zig-out/bin/pm

echo "--- init ---"
$PM init
echo "--- add ---"
$PM add github --username demo-user --password 'demo-password-123' --notes "personal account"
$PM add bank --username demo@example.com --password 'demo-password-456' --notes "savings"
echo "--- list ---"
$PM list
echo "--- get github ---"
$PM get github
echo "--- search (case-insensitive, over name/username/notes) ---"
$PM search GIT
$PM search savings
echo "--- generate a password, add with --generate ---"
$PM gen --length 16
$PM add api --username demo-api --generate --notes "generated entry"
$PM get api
echo "--- export (CSV), remove, re-import ---"
$PM export --format csv --out "$DEMO_DIR/export.csv"
$PM remove bank
$PM list
$PM import "$DEMO_DIR/export.csv" --format csv
$PM list
echo "--- backup + restore ---"
$PM backup "$DEMO_DIR/vault.bak"
$PM remove api
$PM restore --force "$DEMO_DIR/vault.bak"
$PM list
echo "--- remove bank, list again ---"
$PM remove bank
$PM list
echo "--- change master password: old refused, new works ---"
PM_NEW_MASTER_PASSWORD="demo-master-password-v2" $PM change-password
PM_MASTER_PASSWORD=demo-master-password $PM list || true
PM_MASTER_PASSWORD=demo-master-password-v2 $PM list
echo "--- wrong master password is refused ---"
PM_MASTER_PASSWORD=wrong-password $PM list || true
echo "--- demo done (vault was in $DEMO_DIR, now deleted) ---"
