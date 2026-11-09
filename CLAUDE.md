# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Flow-BBS-List (arcanii/Flow-BBS-List, public) is the phonebook of Flow
BBSes that `dial`, the dialer in Flow's app `flow-phonebook`
(arcanii/Flow-Phonebook, private), lists and calls: `phonebook.json`,
the boards' banners in `banners/`, the checks and the signing script.
README.md is its manual, for sysops and the owner both. The design is
the doc "Flow Phonebook — design" (the order of work's step 1 is this
repository).

## Commands

```bash
python3 -m unittest discover -s tests   # the checks' own tests
python3 scripts/check.py                # the phonebook against its format
python3 scripts/check.py --tidy         # lay it out as the checks want it
python3 scripts/check.py --online       # call each board for its key
python3 scripts/check.py --signed       # its signature against keys/phonebook.pub
scripts/sign.sh                         # sign it (the owner, on the Mac)
```

- Python 3.10 or later and nothing outside its standard library: the
  checks run on GitHub's runners as they are. `--online` needs
  `ssh-keyscan`, `--signed` an OpenSSL that knows Ed25519 (3 or later;
  the Mac's `/usr/bin/openssl` is LibreSSL, so Homebrew's, or `OPENSSL`).
- Comments and docs are plain English that say why; tests are named as
  sentences.
- The format lives in three places that must agree: `check.py`
  (`ORDER`, the rules), the README's "A board's entry", and `dial`'s
  reader. Change them together, and bump `format` for anything an older
  `dial` would misread.
- `seen.json` is never on main: the workflow "Seen" force-pushes it to the
  branch `seen`, one commit.

## Never without the user's word

Merging a board, signing (`scripts/sign.sh`), making or exporting the key,
and pushing: the phonebook is what every `dial` trusts for a board's key.
