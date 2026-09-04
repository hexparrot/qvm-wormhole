"""qvm-wormhole-recv: code handling, payload framing, and what it refuses to
write. Nothing here touches a VM, dom0, or the network.

The happy path runs the REAL handler behind a fake qrexec. The hostile cases use
crafted services, because the point is that the client does not trust the
service's declared name, size or digest.
"""

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLIENT = ROOT / "bin" / "qvm-wormhole-recv"
HANDLER = ROOT / "qrexec" / "wormhole.Recv"
sys.path.insert(0, str(ROOT / "share"))
import qvmwh  # noqa: E402

FAKE_QREXEC = """#!/usr/bin/env python3
import os, sys
args = [a for a in sys.argv[1:] if not a.startswith("--")]
os.environ["QREXEC_SERVICE_ARGUMENT"] = args[-1].partition("+")[2]
os.environ["QREXEC_REMOTE_DOMAIN"] = "testvm"
os.execv(sys.executable, [sys.executable, os.environ["FAKE_HANDLER"]])
"""

REFUSING_QREXEC = """#!/bin/sh
echo "Request refused" >&2
exit 126
"""

WORMHOLE_SHIM = """#!/bin/sh
printf '%s' "${WH_RECV_CONTENT:-hello}" > "${WH_RECV_NAME:-got.txt}"
exit 0
"""

# A service that lies about the payload, in the four ways that matter.
def evil_service(name="ok.txt", declared=None, body=b"data", sha=None):
    return """#!/usr/bin/env python3
import sys, json, hashlib
sys.stdin.buffer.readline()
body = %r
head = {"status": "payload", "host": "disp0", "name": %r,
        "size": %s, "sha256": %r}
sys.stdout.write(json.dumps(head) + "\\n")
sys.stdout.flush()
sys.stdout.buffer.write(body)
sys.stdout.buffer.flush()
""" % (body, name,
       len(body) if declared is None else declared,
       sha if sha is not None else hashlib.sha256(body).hexdigest())


class RecvClientCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = pathlib.Path(self.tmp.name)
        self.home = self.d / "home"
        self.home.mkdir()
        self.dest = self.home / "QubesIncoming" / "wormhole"

    def write(self, name, body):
        p = self.d / name
        p.write_text(body)
        p.chmod(0o755)
        return p

    def run_client(self, *args, service=None, qrexec=FAKE_QREXEC, **env_over):
        shim = self.write("qrexec", qrexec)
        handler = self.write("svc", service) if service else HANDLER
        wh = self.write("wormhole", WORMHOLE_SHIM)
        env = dict(os.environ)
        env.update({
            "HOME": str(self.home),
            "DISPLAY": "",
            "QVM_WORMHOLE_QREXEC": str(shim),
            "QVM_WORMHOLE_LIB": str(ROOT / "share"),
            "FAKE_HANDLER": str(handler),
            "WORMHOLE_RECV_BIN": str(wh),
        })
        env.update({k: str(v) for k, v in env_over.items()})
        return subprocess.run([sys.executable, str(CLIENT), *args],
                              capture_output=True, env=env, timeout=120,
                              stdin=subprocess.DEVNULL)

    def landed(self):
        return sorted(p.name for p in self.dest.iterdir()) if self.dest.exists() else []

    # --- code handling ---------------------------------------------------

    def test_a_malformed_code_is_refused_before_any_call(self):
        for code in ["nope", "1-a", "51234-exceed; id", "", "../../x"]:
            with self.subTest(code=code):
                p = self.run_client(code)
                self.assertEqual(p.returncode, 2)
                self.assertEqual(self.landed(), [])

    def test_a_stock_wormhole_code_is_accepted(self):
        p = self.run_client("7-crossover-clockwork")
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    def test_an_uppercase_code_is_normalised(self):
        """Codes are case-sensitive to the PAKE; a human retyping one should not
        be defeated by shift."""
        p = self.run_client("7-CROSSOVER-Clockwork")
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    def test_with_no_code_and_no_way_to_ask_it_fails_cleanly(self):
        p = self.run_client()
        self.assertEqual(p.returncode, 2)
        self.assertIn("no way to ask", p.stderr.decode())

    # --- the happy path, through the real handler ------------------------

    def test_a_whole_receive_lands_the_file(self):
        p = self.run_client("51234-exceed-souvenir",
                            WH_RECV_NAME="report.pdf", WH_RECV_CONTENT="PAYLOAD")
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertEqual(self.landed(), ["report.pdf"])
        got = self.dest / "report.pdf"
        self.assertEqual(got.read_bytes(), b"PAYLOAD")
        self.assertEqual(oct(got.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(self.dest.stat().st_mode & 0o777), "0o700")

    def test_a_second_transfer_does_not_clobber_the_first(self):
        self.run_client("51234-exceed-souvenir",
                        WH_RECV_NAME="a.txt", WH_RECV_CONTENT="first")
        self.run_client("51234-exceed-souvenir",
                        WH_RECV_NAME="a.txt", WH_RECV_CONTENT="second")
        self.assertEqual(self.landed(), ["a.1.txt", "a.txt"])
        self.assertEqual((self.dest / "a.txt").read_bytes(), b"first")

    def test_the_journal_records_the_nameplate_not_the_code(self):
        self.run_client("51234-exceed-souvenir")
        jf = self.home / ".local/state/qvm-wormhole/journal.jsonl"
        rec = json.loads(jf.read_text().splitlines()[-1])
        self.assertEqual(rec["direction"], "recv")
        self.assertEqual(rec["nameplate"], "51234")
        self.assertNotIn("exceed-souvenir", jf.read_text())

    # --- not trusting the service ----------------------------------------

    def test_a_service_supplied_path_cannot_escape_the_output_dir(self):
        """The name originates with the REMOTE SENDER, so this end re-sanitises
        it even though our own service already did."""
        for name in ["../../.bashrc", "/etc/passwd", "..", "a/b/c", "-rf"]:
            with self.subTest(name=name):
                p = self.run_client("51234-exceed-souvenir",
                                    service=evil_service(name=name))
                self.assertEqual(p.returncode, 0, p.stderr.decode())
                for f in self.dest.iterdir():
                    self.assertNotIn("/", f.name)
        self.assertFalse((self.home / ".bashrc").exists())
        self.assertFalse((self.home / "a").exists())

    def test_a_truncated_payload_leaves_nothing_behind(self):
        p = self.run_client("51234-exceed-souvenir",
                            service=evil_service(declared=1000, body=b"short"))
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.landed(), [], "a partial file was left in place")

    def test_a_bad_digest_discards_the_file(self):
        p = self.run_client("51234-exceed-souvenir",
                            service=evil_service(sha="0" * 64))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("mismatch", p.stderr.decode())
        self.assertEqual(self.landed(), [])

    def test_an_oversized_declaration_is_refused_before_reading(self):
        p = self.run_client("51234-exceed-souvenir", "--size-cap", "4",
                            service=evil_service(body=b"much longer than four"))
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.landed(), [])

    def test_a_nonsense_declared_size_is_refused(self):
        for bad in ["0", "-5", "true"]:
            with self.subTest(bad=bad):
                p = self.run_client("51234-exceed-souvenir",
                                    service=evil_service(declared=bad))
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(self.landed(), [])

    # --- policy ----------------------------------------------------------

    def test_a_refusal_is_diagnosed_as_policy(self):
        p = self.run_client("51234-exceed-souvenir", qrexec=REFUSING_QREXEC)
        self.assertEqual(p.returncode, 126)
        self.assertIn("no policy line", p.stderr.decode())
        self.assertEqual(self.landed(), [])


class SharedContractCase(unittest.TestCase):
    def test_both_handlers_use_the_same_code_regex_as_the_library(self):
        """Three copies of this pattern exist. If they drift, transfers fail at
        the far end with 'malformed code' and the cause is three files apart."""
        pats = {qvmwh.CODE_RE.pattern}
        for h in ["wormhole.Send", "wormhole.Recv"]:
            src = (ROOT / "qrexec" / h).read_text()
            pats.add(src.split('CODE_RE = re.compile(r"', 1)[1].split('")', 1)[0])
        self.assertEqual(len(pats), 1, "CODE_RE has drifted: %r" % pats)

    def test_minted_codes_satisfy_that_regex(self):
        words = qvmwh.load_wordlist()
        for _ in range(200):
            self.assertRegex(qvmwh.mint_code(words), qvmwh.CODE_RE)


if __name__ == "__main__":
    unittest.main()
