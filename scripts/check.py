#!/usr/bin/env python3
"""Checks the phonebook of Flow BBSes, phonebook.json, as dial reads it.

Every board's entry is checked against the format (README, "A board's
entry"), with its banner, and the file must be laid out as --tidy writes
it, so a pull request's diff is only its board. Then, as asked:

  --online           calls each board to see it answers with a key it lists
  --changed-from REF only the boards new or changed since REF (a pull request)
  --seen FILE        notes in FILE when each board last answered; one that
                     doesn't is said, not a failure (the scheduled check)
  --signed           checks phonebook.json.sig against keys/phonebook.pub
  --tidy             rewrites the file as it should be laid out

Each problem is a line, and any makes the exit status 1. It needs nothing but
Python 3.10, ssh-keyscan for --online and --seen, and an OpenSSL that knows
Ed25519 for --signed.
"""

import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

FORMAT = 1
# A board's fields, in the order --tidy writes them.
ORDER = ["id", "name", "about", "host", "port", "user", "host_keys", "sysop", "banner", "uses", "flow", "tags"]
OPTIONAL = {"user"}
USES = {"pictures", "models", "effects", "sounds"}
KEY_TYPES = {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"}
BANNER = (640, 160)
BANNER_BYTES = 256 * 1024
MOST_TAGS = 8

WORDS = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
# GitHub's own rule for a name: letters, digits and single dashes inside.
SYSOP = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}\Z")
VERSION = re.compile(r"\d+\.\d+\.\d+\Z")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
HOSTNAME = re.compile(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z")
PNG = b"\x89PNG\r\n\x1a\n"
# What comes before an Ed25519 key's 32 bytes in its DER form, for OpenSSL.
ED25519_DER = bytes.fromhex("302a300506032b6570032100")


def problems(book, root, allow_local=False):
    """What's wrong with the phonebook `book`, whose banners are under `root`."""
    if not isinstance(book, dict):
        return ["the phonebook isn't a JSON object"]
    out = [f"{key} isn't a field the phonebook has" for key in sorted(set(book) - {"format", "boards"})]
    if book.get("format") != FORMAT:
        out.append(f"format is {book.get('format')!r}, not {FORMAT}")
    boards = book.get("boards")
    if not isinstance(boards, list):
        return out + ["boards isn't a list"]
    ids = set()
    for n, board in enumerate(boards, 1):
        name = board.get("id") if isinstance(board, dict) else None
        label = f"board {name!r}" if isinstance(name, str) else f"board {n}"
        out += [f"{label}: {p}" for p in board_problems(board, root, allow_local)]
        if isinstance(name, str):
            if name in ids:
                out.append(f"{label}: another board has this id")
            ids.add(name)
    return out


def board_problems(board, root, allow_local):
    """What's wrong with one board's entry."""
    if not isinstance(board, dict):
        return ["isn't a JSON object"]
    out = [f"{f} isn't a field a board has" for f in sorted(set(board) - set(ORDER))]
    out += [f"{f} is missing" for f in ORDER if f not in board and f not in OPTIONAL]
    has = lambda f: f in board

    def line(f, most):
        v = board[f]
        if not (isinstance(v, str) and 0 < len(v) <= most and v.strip() == v and v.isprintable()):
            out.append(f"{f} must be one line of 1 to {most} characters, no space at either end")

    if has("id") and not (isinstance(board["id"], str) and len(board["id"]) <= 32 and WORDS.match(board["id"])):
        out.append("id must be lowercase letters and digits, single dashes between, at most 32")
    if has("name"):
        line("name", 40)
    if has("about"):
        line("about", 80)
    if has("host"):
        p = host_problem(board["host"], allow_local)
        if p:
            out.append(p)
    if has("port"):
        port = board["port"]
        if not (isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536):
            out.append("port must be a number from 1 to 65535")
    if has("user") and not (isinstance(board["user"], str) and USER.match(board["user"])):
        out.append("user must be a login name: lowercase letters, digits, _ and -, at most 32")
    if has("host_keys"):
        out += keys_problems(board["host_keys"])
    if has("sysop") and not (isinstance(board["sysop"], str) and SYSOP.match(board["sysop"])):
        out.append("sysop must be a GitHub name")
    if has("banner"):
        out += banner_problems(board, root)
    if has("uses"):
        uses = board["uses"]
        if not (isinstance(uses, list) and all(isinstance(u, str) for u in uses)):
            out.append("uses must be a list of " + ", ".join(sorted(USES)))
        else:
            out += [f"uses {u!r}, which isn't one of " + ", ".join(sorted(USES)) for u in uses if u not in USES]
            if len(set(uses)) < len(uses):
                out.append("uses names something twice")
    if has("flow") and not (isinstance(board["flow"], str) and VERSION.match(board["flow"])):
        out.append("flow must be a version of Flow, as 0.1.34")
    if has("tags"):
        tags = board["tags"]
        if not (isinstance(tags, list) and len(tags) <= MOST_TAGS and all(isinstance(t, str) and len(t) <= 20 and WORDS.match(t) for t in tags)):
            out.append(f"tags must be a list of at most {MOST_TAGS} words: lowercase letters and digits, single dashes between, at most 20")
        elif len(set(tags)) < len(tags):
            out.append("tags names something twice")
    return out


def host_problem(host, allow_local):
    """What's wrong with a board's host, if anything: a public name or address,
    since the phonebook is for everyone. --allow-local lets the tests' own
    boards on this machine in."""
    if not isinstance(host, str) or not host:
        return "host must be a name or an address"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return None if address.is_global or allow_local else "host is an address only a local network reaches"
    local = host == "localhost" or host.endswith((".localhost", ".local", ".lan", ".internal", ".home.arpa"))
    if local:
        return None if allow_local else "host is a name only a local network knows"
    return None if HOSTNAME.match(host) else "host isn't a host's name"


def keys_problems(keys):
    """What's wrong with a board's host keys: each its type and its SHA-256
    fingerprint, as ssh-keygen -l prints it."""
    if not (isinstance(keys, list) and keys):
        return ["host_keys must list at least one key"]
    out = []
    for key in keys:
        parts = key.split(" ") if isinstance(key, str) else []
        if len(parts) != 2 or parts[0] not in KEY_TYPES or not FINGERPRINT.match(parts[1]):
            out.append(f"host key {key!r} must be a key's type and its fingerprint, as \"ssh-ed25519 SHA256:…\"")
    if len(set(map(str, keys))) < len(keys):
        out.append("host_keys names a key twice")
    return out


def banner_problems(board, root):
    """What's wrong with a board's banner: a PNG of BANNER's size, named for
    the board, kept here so drawing the directory never calls a board."""
    banner, name = board["banner"], board.get("id")
    if isinstance(name, str) and banner != f"banners/{name}.png":
        return [f"banner must be banners/{name}.png"]
    if not isinstance(banner, str):
        return ["banner must be a file's path"]
    path = os.path.join(root, banner)
    try:
        with open(path, "rb") as f:
            data = f.read(BANNER_BYTES + 1)
    except OSError:
        return [f"banner {banner} isn't there"]
    if len(data) > BANNER_BYTES:
        return [f"banner {banner} is over {BANNER_BYTES // 1024} KiB"]
    if not data.startswith(PNG) or data[12:16] != b"IHDR":
        return [f"banner {banner} isn't a PNG"]
    size = struct.unpack(">II", data[16:24])
    if size != BANNER:
        return [f"banner {banner} is {size[0]} × {size[1]}, not {BANNER[0]} × {BANNER[1]}"]
    return []


def tidy(book):
    """The phonebook as it should be laid out: boards by id, each one's
    fields in ORDER, two spaces in, a newline at the end."""
    boards = sorted(book["boards"], key=lambda b: b["id"])
    laid = [{f: b[f] for f in ORDER if f in b} for b in boards]
    return json.dumps({"format": book["format"], "boards": laid}, indent=2, ensure_ascii=False) + "\n"


def fingerprint(blob):
    """A key's SHA-256 fingerprint as ssh-keygen -l prints it, from the key
    as ssh-keyscan writes it (base64)."""
    digest = hashlib.sha256(base64.b64decode(blob)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def scan(host, port, run=subprocess.run):
    """The keys a host serves, as (type, fingerprint): none if it doesn't
    answer."""
    try:
        done = run(["ssh-keyscan", "-T", "5", "-p", str(port), host], capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        sys.exit("check.py: ssh-keyscan isn't on the PATH")
    except subprocess.TimeoutExpired:
        return []
    keys = []
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            keys.append((parts[1], fingerprint(parts[2])))
    return keys


def call(board, run=subprocess.run):
    """Calls a board: None if it answers with a key it lists, else why not."""
    served = scan(board["host"], board["port"], run)
    where = f"{board['host']}:{board['port']}"
    if not served:
        return f"{where} didn't answer"
    listed = {tuple(k.split(" ")) for k in board["host_keys"]}
    if any(key in listed for key in served):
        return None
    return f"{where} answered with keys it doesn't list: " + ", ".join(f"{t} {f}" for t, f in served)


def changed(book, before):
    """The ids of the boards new or changed since the phonebook `before`."""
    old = {b["id"]: b for b in before.get("boards", []) if isinstance(b, dict) and "id" in b}
    return {b["id"] for b in book["boards"] if old.get(b["id"]) != b}


def noted(seen, book, answered, now):
    """seen.json again: `now` for each board that answered, the time before
    kept for one that didn't, and none for a board no longer listed."""
    listed = {b["id"] for b in book["boards"]}
    times = {k: v for k, v in seen.get("seen", {}).items() if k in listed}
    times.update({name: now for name in answered})
    return {"format": FORMAT, "seen": dict(sorted(times.items()))}


def verify(data, signature, public):
    """Whether `signature` (base64, as Sparkle's sign_update -p prints it) is
    `data` signed with the Ed25519 key `public` (base64, as generate_keys -p
    prints it). OpenSSL does the checking."""
    try:
        key, sig = base64.b64decode(public.strip(), validate=True), base64.b64decode(signature.strip(), validate=True)
    except ValueError:
        return False
    if len(key) != 32 or len(sig) != 64:
        return False
    openssl = os.environ.get("OPENSSL") or shutil.which("openssl")
    if not openssl:
        sys.exit("check.py: openssl isn't on the PATH (or set OPENSSL)")
    with tempfile.TemporaryDirectory() as d:
        pem, sig_file, data_file = (os.path.join(d, n) for n in ("key.pem", "sig", "data"))
        with open(pem, "w") as f:
            f.write("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(ED25519_DER + key).decode() + "\n-----END PUBLIC KEY-----\n")
        with open(sig_file, "wb") as f:
            f.write(sig)
        with open(data_file, "wb") as f:
            f.write(data)
        done = subprocess.run([openssl, "pkeyutl", "-verify", "-pubin", "-inkey", pem, "-rawin", "-in", data_file, "-sigfile", sig_file], capture_output=True, text=True)
    said = done.stdout + done.stderr
    if done.returncode == 0 and "Signature Verified Successfully" in said:
        return True
    if "Verification Failure" in said:
        return False
    sys.exit(f"check.py: {openssl} couldn't check an Ed25519 signature (OpenSSL 3 or later can): {said.strip()}")


def read_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except OSError as e:
        sys.exit(f"check.py: can't read {what} {path}: {e.strerror}")
    except json.JSONDecodeError as e:
        sys.exit(f"check.py: {path} isn't JSON: {e.msg}, line {e.lineno} column {e.colno}")


def git_show(ref, path):
    """The phonebook as it was at `ref`, or an empty one where it wasn't."""
    done = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, text=True)
    return json.loads(done.stdout) if done.returncode == 0 else {"boards": []}


def main():
    ap = argparse.ArgumentParser(description="Checks the phonebook of Flow BBSes.")
    ap.add_argument("phonebook", nargs="?", default="phonebook.json")
    ap.add_argument("--online", action="store_true", help="call each board")
    ap.add_argument("--changed-from", metavar="REF", help="call only the boards new or changed since REF")
    ap.add_argument("--seen", metavar="FILE", help="note in FILE when each board last answered")
    ap.add_argument("--signed", action="store_true", help="check the phonebook's signature")
    ap.add_argument("--signature", metavar="FILE", help="the signature to check (the phonebook's .sig)")
    ap.add_argument("--key", metavar="FILE", default=None, help="the public key (keys/phonebook.pub)")
    ap.add_argument("--tidy", action="store_true", help="rewrite the phonebook as it should be laid out")
    ap.add_argument("--allow-local", action="store_true", help="let in boards on this machine or its network (tests)")
    args = ap.parse_args()

    path = args.phonebook
    root = os.path.dirname(os.path.abspath(path))
    book = read_json(path, "the phonebook")
    found = problems(book, root, args.allow_local)
    if found:
        for p in found:
            print(f"{path}: {p}")
        return 1
    if args.tidy:
        with open(path, "w", encoding="utf-8") as f:
            f.write(tidy(book))
    with open(path, encoding="utf-8") as f:
        if f.read() != tidy(book):
            print(f"{path}: isn't laid out as scripts/check.py --tidy writes it")
            return 1

    failed = False
    if args.online or args.seen:
        boards = book["boards"]
        if args.changed_from:
            wanted = changed(book, git_show(args.changed_from, os.path.relpath(path)))
            boards = [b for b in boards if b["id"] in wanted]
        answered = set()
        for board in boards:
            why = call(board)
            if why is None:
                answered.add(board["id"])
            else:
                print(f"{path}: board {board['id']!r}: {why}")
                failed = failed or not args.seen
        if args.seen:
            seen = read_json(args.seen, "seen") if os.path.exists(args.seen) else {"format": FORMAT, "seen": {}}
            now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
            with open(args.seen, "w", encoding="utf-8") as f:
                f.write(json.dumps(noted(seen, book, answered, now), indent=2) + "\n")
        print(f"{path}: {len(answered)} of {len(boards)} called answered with a key they list")

    if args.signed:
        signature = args.signature or path + ".sig"
        key = args.key or os.path.relpath(os.path.join(root, "keys", "phonebook.pub"))
        for need, what in ((signature, "signature"), (key, "public key")):
            if not os.path.exists(need):
                print(f"{path}: its {what} {need} isn't there")
                return 1
        with open(path, "rb") as f, open(signature) as s, open(key) as k:
            if not verify(f.read(), s.read(), k.read()):
                print(f"{path}: {signature} isn't its signature by {key}: sign it again (scripts/sign.sh)")
                return 1
        print(f"{path}: signed with the phonebook's key")

    if failed:
        return 1
    count = len(book["boards"])
    print(f"{path}: {count} board{'' if count == 1 else 's'}, nothing wrong")
    return 0


if __name__ == "__main__":
    sys.exit(main())
