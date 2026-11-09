#!/usr/bin/env bash
# Signs phonebook.json with the phonebook's own key, as Flow's releases are
# signed on the Mac: Sparkle's sign_update, the private key in the Keychain
# under the account Flow-Phonebook. Never Flow's update key, which signs
# code. The signature goes in phonebook.json.sig once check.py has found it
# holds against keys/phonebook.pub, the public key dial carries; nothing that
# fails the checks is signed.
#
#   scripts/sign.sh                       after merging a board
#   scripts/sign.sh --ed-key-file <file>  the private key from a file instead
#
# sign_update is taken from SIGN_UPDATE, else from Flow's checkout beside this
# one (../Flow_Terminal/target/sparkle-*), which Flow's release script fetches.
set -euo pipefail

die() { echo "sign.sh: $*" >&2; exit 1; }
cd "$(dirname "$0")/.."

key=(--account Flow-Phonebook)
case "${1:-}" in
  "") ;;
  --ed-key-file) [[ -n "${2:-}" ]] || die "--ed-key-file needs the key's file"; key=(--ed-key-file "$2") ;;
  *) die "usage: scripts/sign.sh [--ed-key-file <file>]" ;;
esac

tool="${SIGN_UPDATE:-}"
if [[ -z "$tool" ]]; then
  for c in ../Flow_Terminal/target/sparkle-*/bin/sign_update; do [[ -x "$c" ]] && { tool="$c"; break; }; done
fi
[[ -n "$tool" ]] || die "sign_update not found: run Flow's macos/scripts/release.sh once (it fetches Sparkle), or set SIGN_UPDATE"
[[ -f keys/phonebook.pub ]] || die "keys/phonebook.pub isn't there: make the key first (README, \"The key\")"

python3 scripts/check.py phonebook.json
"$tool" "${key[@]}" -p phonebook.json > phonebook.json.sig.new || { rm -f phonebook.json.sig.new; die "sign_update couldn't sign it"; }
if ! python3 scripts/check.py --signed --signature phonebook.json.sig.new phonebook.json; then
  rm -f phonebook.json.sig.new
  die "the signature doesn't hold against keys/phonebook.pub: was it signed with the phonebook's key?"
fi
mv phonebook.json.sig.new phonebook.json.sig
echo "Signed: commit phonebook.json.sig and push it."
