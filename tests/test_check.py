"""The checks' own tests: python3 -m unittest discover -s tests

Each phonebook here is made in a folder of its own, its banners drawn as it
goes. The signature tests make a key with OpenSSL, and the last also signs
with Sparkle's sign_update, as scripts/sign.sh does, where it's found.
"""

import base64
import copy
import glob
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("check", os.path.join(HERE, "..", "scripts", "check.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

KEY = "ssh-ed25519 SHA256:" + "A" * 43


def png(width, height):
    """A PNG of `width` × `height` black pixels."""
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    rows = b"".join(b"\0" + b"\0" * 3 * width for _ in range(height))
    return check.PNG + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")


def board(ident="green-room", **changes):
    """A good board's entry, but for `changes`."""
    b = {
        "id": ident,
        "name": "The Green Room",
        "about": "Games, art and talk, drawn for Flow",
        "host": "bbs.example.org",
        "port": 22,
        "user": "guest",
        "host_keys": [KEY],
        "sysop": "someone",
        "banner": f"banners/{ident}.png",
        "uses": ["pictures", "sounds"],
        "flow": "0.1.34",
        "tags": ["games", "art"],
    }
    b.update(changes)
    return b


class Folder(unittest.TestCase):
    """Each test gets a folder holding its phonebook's banners."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.mkdir(os.path.join(self.root, "banners"))

    def tearDown(self):
        shutil.rmtree(self.root)

    def banner(self, name, data=None):
        with open(os.path.join(self.root, "banners", f"{name}.png"), "wb") as f:
            f.write(png(*check.BANNER) if data is None else data)

    def problems(self, *boards, allow_local=False):
        for b in boards:
            if isinstance(b, dict) and isinstance(b.get("id"), str) and not os.path.exists(os.path.join(self.root, "banners", f"{b['id']}.png")):
                self.banner(b["id"])
        return check.problems({"format": 1, "boards": list(boards)}, self.root, allow_local)


class TheFormat(Folder):
    def test_a_good_phonebook_has_no_problems(self):
        b = board("night-owl")
        del b["user"]
        self.assertEqual(self.problems(board(), b), [], "user may be left out")
        self.assertEqual(check.problems({"format": 1, "boards": []}, self.root), [], "an empty phonebook is a good one")
        for bad in ["Guest", "a guest", "", None]:
            self.assertEqual(self.problems(board(user=bad)), ["board 'green-room': user must be a login name: lowercase letters, digits, _ and -, at most 32"], repr(bad))

    def test_the_phonebook_itself_must_be_format_1_with_a_list_of_boards(self):
        self.assertEqual(check.problems([], self.root), ["the phonebook isn't a JSON object"])
        self.assertEqual(check.problems({"format": 2, "boards": [], "extra": 1}, self.root), ["extra isn't a field the phonebook has", "format is 2, not 1"])
        self.assertEqual(check.problems({"format": 1, "boards": {}}, self.root), ["boards isn't a list"])

    def test_each_missing_field_is_named_and_an_unknown_one_too(self):
        b = board()
        del b["host_keys"], b["flow"]
        b["hostkeys"] = [KEY]
        self.assertEqual(self.problems(b), ["board 'green-room': hostkeys isn't a field a board has", "board 'green-room': host_keys is missing", "board 'green-room': flow is missing"])

    def test_ids_are_lowercase_words_and_no_two_boards_share_one(self):
        for bad in ["Green", "green_room", "-green", "green--room", "", "a" * 33]:
            self.assertTrue(self.problems(board(bad, banner="banners/x.png"))[0].endswith("id must be lowercase letters and digits, single dashes between, at most 32"), bad)
        self.assertEqual(self.problems(board(), board()), ["board 'green-room': another board has this id"])

    def test_names_and_lines_are_one_line_of_bounded_length(self):
        for bad in ["", " The Green Room", "Green\nRoom", "x" * 41]:
            self.assertEqual(self.problems(board(name=bad)), ["board 'green-room': name must be one line of 1 to 40 characters, no space at either end"], repr(bad))
        self.assertEqual(self.problems(board(about="x" * 81)), ["board 'green-room': about must be one line of 1 to 80 characters, no space at either end"])
        self.assertEqual(self.problems(board(name="Café Ümlaut ☕")), [], "letters past ASCII are welcome")

    def test_a_host_on_this_machine_or_its_network_is_kept_out_unless_allowed(self):
        for host in ["localhost", "127.0.0.1", "::1", "192.168.1.20", "10.0.0.5", "fd00::1", "board.local", "board.lan"]:
            found = self.problems(board(host=host))
            self.assertEqual(len(found), 1, host)
            self.assertIn("only a local network", found[0], host)
            self.assertEqual(self.problems(board(host=host), allow_local=True), [], host)
        for host in ["bbs.example.org", "93.184.215.14", "2606:4700::1111"]:
            self.assertEqual(self.problems(board(host=host)), [], host)
        for host in ["", "bbs", "bbs..example.org", "bbs.example.org:22", "http://bbs.example.org", 7]:
            self.assertTrue(self.problems(board(host=host)), repr(host))

    def test_a_port_is_a_number_from_1_to_65535(self):
        for bad in [0, 65536, "22", True, 22.0]:
            self.assertEqual(self.problems(board(port=bad)), ["board 'green-room': port must be a number from 1 to 65535"], repr(bad))
        self.assertEqual(self.problems(board(port=2222)), [])

    def test_host_keys_are_a_type_and_a_sha256_fingerprint(self):
        self.assertEqual(self.problems(board(host_keys=[KEY, "ecdsa-sha2-nistp256 SHA256:" + "b" * 43])), [])
        for bad in [[], "x", ["SHA256:" + "A" * 43], ["ssh-dss SHA256:" + "A" * 43], ["ssh-ed25519 MD5:aa:bb"], ["ssh-ed25519 SHA256:" + "A" * 42]]:
            self.assertTrue(self.problems(board(host_keys=bad)), repr(bad))
        self.assertEqual(self.problems(board(host_keys=[KEY, KEY])), ["board 'green-room': host_keys names a key twice"])

    def test_sysop_is_a_github_name(self):
        for good in ["someone", "Some-One", "a", "a" * 39]:
            self.assertEqual(self.problems(board(sysop=good)), [], good)
        for bad in ["-someone", "some--one", "someone-", "some one", "a" * 40, "@someone"]:
            self.assertEqual(self.problems(board(sysop=bad)), ["board 'green-room': sysop must be a GitHub name"], bad)

    def test_the_banner_is_its_ids_png_at_640_by_160_and_no_bigger_than_256_kib(self):
        self.assertEqual(self.problems(board(banner="banners/other.png")), ["board 'green-room': banner must be banners/green-room.png"])
        self.banner("green-room", png(640, 200))
        self.assertEqual(self.problems(board()), ["board 'green-room': banner banners/green-room.png is 640 × 200, not 640 × 160"])
        self.banner("green-room", b"GIF89a" + b"\0" * 100)
        self.assertEqual(self.problems(board()), ["board 'green-room': banner banners/green-room.png isn't a PNG"])
        self.banner("green-room", png(640, 160) + b"\0" * check.BANNER_BYTES)
        self.assertEqual(self.problems(board()), ["board 'green-room': banner banners/green-room.png is over 256 KiB"])
        os.remove(os.path.join(self.root, "banners", "green-room.png"))
        self.assertEqual(check.problems({"format": 1, "boards": [board()]}, self.root), ["board 'green-room': banner banners/green-room.png isn't there"])

    def test_uses_flow_and_tags_come_from_their_lists(self):
        self.assertEqual(self.problems(board(uses=["pictures", "models", "effects", "sounds"])), [])
        self.assertEqual(self.problems(board(uses=["pictures", "video"])), ["board 'green-room': uses 'video', which isn't one of effects, models, pictures, sounds"])
        self.assertEqual(self.problems(board(uses=["sounds", "sounds"])), ["board 'green-room': uses names something twice"])
        for bad in ["0.1", "v0.1.34", "0.1.34-beta", 34]:
            self.assertEqual(self.problems(board(flow=bad)), ["board 'green-room': flow must be a version of Flow, as 0.1.34"], repr(bad))
        self.assertEqual(self.problems(board(tags=[])), [])
        for bad in [["Games"], ["a"] * 9, ["games and art"], "games"]:
            self.assertTrue(self.problems(board(tags=bad)), repr(bad))
        self.assertEqual(self.problems(board(tags=["art", "art"])), ["board 'green-room': tags names something twice"])

    def test_tidy_sorts_the_boards_and_lays_out_each_field_in_order(self):
        b = board("night-owl")
        shuffled = {k: b[k] for k in reversed(check.ORDER)}
        text = check.tidy({"format": 1, "boards": [shuffled, board()]})
        laid = json.loads(text)
        self.assertEqual([x["id"] for x in laid["boards"]], ["green-room", "night-owl"])
        self.assertEqual(list(laid["boards"][1]), check.ORDER)
        self.assertTrue(text.endswith("}\n") and '\n  "boards": [\n    {\n      "id": "green-room",' in text, text[:120])
        self.assertIn('"name": "Café"', check.tidy({"format": 1, "boards": [board(name="Café")]}), "letters kept as they are, not escaped")


class Calling(unittest.TestCase):
    """--online and --seen, with ssh-keyscan's output made up."""

    @staticmethod
    def keyscan(lines, code=0):
        return lambda cmd, **_: subprocess.CompletedProcess(cmd, code, stdout="".join(l + "\n" for l in lines), stderr="")

    def test_a_fingerprint_is_the_one_ssh_keygen_prints(self):
        if not shutil.which("ssh-keygen"):
            self.skipTest("no ssh-keygen")
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", os.path.join(d, "k")], check=True)
            with open(os.path.join(d, "k.pub")) as f:
                kind, blob = f.read().split()[:2]
            printed = subprocess.run(["ssh-keygen", "-l", "-E", "sha256", "-f", os.path.join(d, "k.pub")], capture_output=True, text=True, check=True).stdout.split()[1]
        self.assertEqual(check.fingerprint(blob), printed)

    def test_a_board_answers_when_it_serves_a_key_it_lists(self):
        blob = base64.b64encode(b"a key").decode()
        served = self.keyscan(["# bbs.example.org:22 SSH-2.0-Board", f"bbs.example.org ssh-ed25519 {blob}", "bbs.example.org ssh-rsa " + base64.b64encode(b"another").decode()])
        self.assertIsNone(check.call(board(host_keys=["ssh-ed25519 " + check.fingerprint(blob)]), served))
        self.assertIsNone(check.call(board(host_keys=[KEY, "ssh-ed25519 " + check.fingerprint(blob)]), served), "a key listed ahead of a change is fine")

    def test_a_board_that_doesnt_answer_or_serves_another_key_is_said(self):
        self.assertEqual(check.call(board(), self.keyscan([], 1)), "bbs.example.org:22 didn't answer")
        blob = base64.b64encode(b"a key").decode()
        said = check.call(board(), self.keyscan([f"bbs.example.org ssh-ed25519 {blob}"]))
        self.assertEqual(said, f"bbs.example.org:22 answered with keys it doesn't list: ssh-ed25519 {check.fingerprint(blob)}")
        same_print_other_type = check.call(board(host_keys=["ssh-rsa " + check.fingerprint(blob)]), self.keyscan([f"bbs.example.org ssh-ed25519 {blob}"]))
        self.assertIsNotNone(same_print_other_type, "a key's type counts too")

    def test_only_boards_new_or_changed_are_called_for_a_pull_request(self):
        before = {"format": 1, "boards": [board(), board("night-owl")]}
        after = copy.deepcopy(before)
        after["boards"][1]["port"] = 2222
        after["boards"].append(board("tea-house"))
        self.assertEqual(check.changed(after, before), {"night-owl", "tea-house"})
        self.assertEqual(check.changed(before, {"boards": []}), {"green-room", "night-owl"})

    def test_seen_keeps_the_last_time_of_a_board_that_didnt_answer_and_forgets_one_gone(self):
        book = {"format": 1, "boards": [board(), board("night-owl")]}
        before = {"format": 1, "seen": {"green-room": "2026-11-09T09:00Z", "night-owl": "2026-11-09T09:00Z", "gone": "2026-11-01T00:00Z"}}
        after = check.noted(before, book, {"night-owl"}, "2026-11-09T10:00Z")
        self.assertEqual(after, {"format": 1, "seen": {"green-room": "2026-11-09T09:00Z", "night-owl": "2026-11-09T10:00Z"}})


def openssl_signs():
    """Whether this machine's OpenSSL can make and check Ed25519 signatures."""
    openssl = os.environ.get("OPENSSL") or shutil.which("openssl")
    if not openssl:
        return None
    with tempfile.TemporaryDirectory() as d:
        made = subprocess.run([openssl, "genpkey", "-algorithm", "ed25519", "-out", os.path.join(d, "k")], capture_output=True)
    return openssl if made.returncode == 0 else None


class Signing(unittest.TestCase):
    """--signed: the phonebook's signature against its public key."""

    def setUp(self):
        self.openssl = openssl_signs()
        if not self.openssl:
            self.skipTest("no OpenSSL that knows Ed25519")
        self.dir = tempfile.mkdtemp()
        self.private = os.path.join(self.dir, "key.pem")
        subprocess.run([self.openssl, "genpkey", "-algorithm", "ed25519", "-out", self.private], check=True)
        der = subprocess.run([self.openssl, "pkey", "-in", self.private, "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout
        self.public = base64.b64encode(der[-32:]).decode()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def sign(self, data):
        path = os.path.join(self.dir, "data")
        with open(path, "wb") as f:
            f.write(data)
        sig = subprocess.run([self.openssl, "pkeyutl", "-sign", "-inkey", self.private, "-rawin", "-in", path], capture_output=True, check=True).stdout
        return base64.b64encode(sig).decode()

    def test_a_signature_holds_for_its_phonebook_and_key_alone(self):
        data = b'{\n  "format": 1,\n  "boards": []\n}\n'
        sig = self.sign(data)
        self.assertTrue(check.verify(data, sig + "\n", self.public + "\n"))
        self.assertFalse(check.verify(data.replace(b"[]", b"[ ]"), sig, self.public), "a byte changed")
        other = base64.b64encode(bytes(32)).decode()
        self.assertFalse(check.verify(data, sig, other), "another key")
        self.assertFalse(check.verify(data, "not base64!", self.public))
        self.assertFalse(check.verify(data, base64.b64encode(b"short").decode(), self.public))

    def test_sparkles_sign_update_makes_a_signature_that_holds(self):
        found = [os.environ["SIGN_UPDATE"]] if os.environ.get("SIGN_UPDATE") else glob.glob(os.path.join(HERE, "..", "..", "Flow_Terminal", "target", "sparkle-*", "bin", "sign_update"))
        if not found:
            self.skipTest("no Sparkle sign_update here (it's on the Mac beside Flow's checkout)")
        der = subprocess.run([self.openssl, "pkey", "-in", self.private, "-outform", "DER"], capture_output=True, check=True).stdout
        seed = os.path.join(self.dir, "seed")
        with open(seed, "w") as f:
            f.write(base64.b64encode(der[-32:]).decode())
        book = os.path.join(self.dir, "phonebook.json")
        data = b'{\n  "format": 1,\n  "boards": []\n}\n'
        with open(book, "wb") as f:
            f.write(data)
        sig = subprocess.run([found[0], "--ed-key-file", seed, "-p", book], capture_output=True, text=True, check=True).stdout
        self.assertTrue(check.verify(data, sig, self.public))


if __name__ == "__main__":
    unittest.main()
