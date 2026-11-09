# Flow BBS List

The phonebook of Flow BBSes: the boards that `dial`, the dialer in
Flow's app `flow-phonebook`, lists and calls. It's public, so anyone can
read it and anyone running a board can ask to be in it.

`dial` reads `phonebook.json` from here, checks it against
`phonebook.json.sig` with the public key it carries, and draws each
board's banner from `banners/`. When each board last answered is on the
branch `seen`. A board's host keys are pinned here: `dial` ends a call
before sending anything if a board answers with a key its entry doesn't
list, so the phonebook is what stops a fake board.

## Adding a board

1. Fork this repository. Add your board's entry to `phonebook.json`
   and its banner as `banners/<id>.png`.
2. Lay the file out and check it, with Python 3.10 or later:

   ```
   python3 scripts/check.py --tidy
   python3 scripts/check.py --online
   ```

   `--tidy` sorts the boards by `id` and writes each one's fields in
   order, so your pull request's diff is your board alone. `--online`
   calls each board to see it answers with a key it lists.
3. Open a pull request. Its checks run the same, calling only the boards
   it adds or changes. The phonebook's owner reviews it, merges it, and
   signs the phonebook again.

To change your board (a new host, a new key), send a pull request the
same way. To change keys without a gap, list the new key beside the old
one first, change the board's key, then take the old one out.

## A board's entry

```json
{
  "id": "green-room",
  "name": "The Green Room",
  "about": "Games, art and talk, drawn for Flow",
  "host": "bbs.example.org",
  "port": 22,
  "user": "guest",
  "host_keys": ["ssh-ed25519 SHA256:..."],
  "sysop": "your-github-name",
  "banner": "banners/green-room.png",
  "uses": ["pictures", "models", "effects", "sounds"],
  "flow": "0.1.34",
  "tags": ["games", "art"]
}
```

| Field | What it holds |
| --- | --- |
| `id` | What `dial` takes: lowercase letters and digits, single dashes between, at most 32. No two boards share one. |
| `name` | Shown in the directory: one line, at most 40 characters. |
| `about` | Shown under its name: one line, at most 80. |
| `host` | A public name or address. One only a local network knows (`localhost`, `192.168.…`, `.local`) isn't taken. |
| `port` | 1 to 65535. |
| `user` | The login `dial` offers, with no password: a guest login. Left out, it's the caller's own name, for the sign-ups `dial` will take later. |
| `host_keys` | Each of the board's keys: its type and its SHA-256 fingerprint. At least one. |
| `sysop` | Who runs it: a GitHub name, to tell about it. |
| `banner` | `banners/<id>.png`. |
| `uses` | What it draws in Flow: any of `pictures`, `models`, `effects`, `sounds`. Shown as marks in the directory. |
| `flow` | The oldest Flow it needs. `dial` on an older Flow says which to update to. |
| `tags` | At most 8 words for `dial --find`, each as an `id` is, at most 20. |

A board's host keys, as `dial` checks them:

```
ssh-keyscan -p 22 bbs.example.org | ssh-keygen -lf -
```

which prints `256 SHA256:… bbs.example.org (ED25519)` for each. Write it
as `"ssh-ed25519 SHA256:…"` (`ecdsa-sha2-nistp256`, `-nistp384`,
`-nistp521` and `ssh-rsa` for the others).

## Banners

A board's banner is a PNG, exactly 640 × 160 pixels and at most 256 KiB,
at `banners/<id>.png`. In Flow it's drawn as a picture beside the board's
name; in other terminals in half blocks. It lives here, not on the board,
so drawing the directory never calls a board from the user's machine.

## The checks

`scripts/check.py` checks the phonebook as `dial` reads it. Each problem
is a line, and any makes it fail:

- the file is `{"format": 1, "boards": [...]}`, laid out as `--tidy`
  writes it;
- each board has the fields above and no others, each as the table says;
- each banner is there, a PNG of 640 × 160, no bigger than 256 KiB;
- with `--online`, each board answers with a key it lists;
- with `--signed`, `phonebook.json.sig` is the phonebook signed with the
  phonebook's key (`keys/phonebook.pub`).

Its own tests: `python3 -m unittest discover -s tests`.

## The signature

The phonebook is signed with an Ed25519 key of its own, so a copy from
anywhere (a mirror, or a hijacked account) can't change a board's pinned
key. It's kept apart from Flow's update key, which signs Flow's code.
`dial` carries the public key, `keys/phonebook.pub`, and keeps the copy it
last found signed when a newer one doesn't hold.

After merging, the owner signs on the Mac, as Flow's releases are signed:

```
git pull
scripts/sign.sh
git add phonebook.json.sig && git commit -m "Sign the phonebook" && git push
```

`sign.sh` checks the phonebook, signs it with Sparkle's `sign_update`
(the private key in the Keychain under the account `Flow-Phonebook`), and
keeps the signature only once it holds against `keys/phonebook.pub`.
Until it's signed, main's check fails, as a reminder.

### The key

Made once, on the Mac, with Sparkle's tools from Flow's checkout:

```
../Flow_Terminal/target/sparkle-*/bin/generate_keys --account Flow-Phonebook
../Flow_Terminal/target/sparkle-*/bin/generate_keys --account Flow-Phonebook -p > keys/phonebook.pub
```

Keep a copy of the private key somewhere safe
(`generate_keys --account Flow-Phonebook -x <file>`): without it the
phonebook can't be signed again, and every `dial` would need a new
public key.

## Which boards answered

Each hour a scheduled check calls every board, and writes when each last
answered with a key it lists to `seen.json` on the branch `seen`:

```json
{
  "format": 1,
  "seen": {
    "green-room": "2026-11-09T10:17Z"
  }
}
```

A board that doesn't answer keeps the time it last did. The branch holds
one commit, replaced each time, so main's history never meets it. GitHub
stops a schedule after 60 days without a push; running the workflow
"Seen" by hand starts it again.

## Licence

The phonebook and the scripts are under the MIT licence or the Apache
licence 2.0, at your choice (`LICENSE-MIT`, `LICENSE-APACHE`). A board
added here is under the same.
