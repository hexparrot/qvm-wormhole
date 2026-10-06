"""wormhole.Recv: verb table, header validation, and the three offer types.

A shim stands in for `wormhole receive`; it writes into the handler's cwd, which
is the work directory the handler passes as --output-file. No VM, no network.
"""

import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HANDLER = ROOT / "qrexec" / "wormhole.Recv"
POLICY = ROOT / "qrexec" / "30-wormhole.policy"

# magic-wormhole offers three kinds of transfer -- message, file, directory --
# and only one is in scope. The shim can produce each, plus failure modes.
SHIM = """#!/bin/sh
printf '%s\\n' "$*" >> "$WH_TEST_CALLS"
case "${WH_RECV_MODE:-file}" in
  file)  printf '%s' "${WH_RECV_CONTENT:-hello}" > "${WH_RECV_NAME:-got.txt}" ;;
  text)  : ;;
  dir)   mkdir -p "${WH_RECV_NAME:-adir}" ;;
  multi) : > a.txt ; : > b.txt ;;
  fail)  echo "Sending..." >&2 ; echo "mailbox is crowded" >&2 ; exit 1 ;;
esac
exit 0
"""


def header(**over):
    h = {"code": "51234-exceed-souvenir", "size_cap": 1 << 20, "timeout": 120}
    h.update(over)
    return (json.dumps(h) + "\n").encode()


class RecvHandlerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = pathlib.Path(self.tmp.name)
        self.home = d / "home"
        self.home.mkdir()
        self.calls = d / "calls"
        self.shim = d / "wormhole"
        self.shim.write_text(SHIM)
        self.shim.chmod(0o755)

    def run_handler(self, arg, stdin=b"", **extra):
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.home),
            "QREXEC_SERVICE_ARGUMENT": arg,
            "QREXEC_REMOTE_DOMAIN": "testvm",
            "WH_TEST_CALLS": str(self.calls),
            "WORMHOLE_RECV_BIN": str(self.shim),
        }
        env.update({k: str(v) for k, v in extra.items()})
        return subprocess.run([str(HANDLER)], input=stdin, env=env,
                              capture_output=True, timeout=60)

    def commands(self):
        if not self.calls.exists():
            return []
        return [l for l in self.calls.read_text().splitlines() if l.strip()]

    @staticmethod
    def parse(out):
        """JSON status lines, then one payload header, then raw bytes."""
        msgs, rest = [], out
        while True:
            nl = rest.find(b"\n")
            if nl < 0:
                break
            try:
                msg = json.loads(rest[:nl].decode(errors="replace"))
            except ValueError:
                break
            msgs.append(msg)
            rest = rest[nl + 1:]
            if msg.get("status") == "payload":
                return msgs, rest[:msg["size"]]
        return msgs, b""

    # --- verb table -----------------------------------------------------

    def test_the_file_verb_receives_and_hands_back_the_bytes(self):
        p = self.run_handler("file", header(),
                             WH_RECV_NAME="report.pdf", WH_RECV_CONTENT="PAYLOAD")
        self.assertEqual(p.returncode, 0, p.stderr)
        msgs, payload = self.parse(p.stdout)
        self.assertEqual(payload, b"PAYLOAD")
        head = [m for m in msgs if m["status"] == "payload"][0]
        self.assertEqual(head["name"], "report.pdf")
        self.assertEqual(head["size"], 7)
        self.assertEqual(head["sha256"], hashlib.sha256(b"PAYLOAD").hexdigest())

    def test_the_code_is_passed_to_wormhole_and_nothing_else_runs(self):
        self.run_handler("file", header())
        self.assertEqual(len(self.commands()), 1)
        self.assertIn("receive --accept-file", self.commands()[0])
        self.assertNotIn("--output-file", self.commands()[0])
        self.assertIn("51234-exceed-souvenir", self.commands()[0])

    def test_everything_else_is_refused_and_runs_nothing(self):
        for arg in ["", "File", "file;id", "$(id)", "../file", "file file",
                    "--help", "send", "recv", "text"]:
            with self.subTest(arg=arg):
                p = self.run_handler(arg, b'{"junk":1}\n')
                self.assertEqual(p.returncode, 2, "arg %r was not refused" % arg)
                self.assertIn("refused", p.stderr.decode())
                self.assertEqual(self.commands(), [])

    def test_policy_admits_exactly_the_handler_verbs(self):
        allowed = set()
        for line in POLICY.read_text().splitlines():
            f = line.split("#", 1)[0].split()
            if len(f) >= 5 and f[0] == "wormhole.Recv" and f[-1] == "allow":
                allowed.add(f[1].lstrip("+"))
        verbs = set(eval(HANDLER.read_text().split("VERBS = ", 1)[1]
                         .split("\n", 1)[0]))
        self.assertEqual(allowed, verbs)

    # --- the offer types out of scope -----------------------------------

    def test_a_text_transfer_is_a_clean_error_not_a_crash(self):
        p = self.run_handler("file", header(), WH_RECV_MODE="text")
        self.assertNotEqual(p.returncode, 0)
        msgs, _ = self.parse(p.stdout)
        self.assertIn("text message", msgs[-1]["message"])

    def test_a_directory_transfer_is_a_clean_error(self):
        p = self.run_handler("file", header(), WH_RECV_MODE="dir")
        self.assertNotEqual(p.returncode, 0)
        msgs, _ = self.parse(p.stdout)
        self.assertIn("directory", msgs[-1]["message"])

    def test_more_than_one_entry_is_refused(self):
        p = self.run_handler("file", header(), WH_RECV_MODE="multi")
        self.assertNotEqual(p.returncode, 0)

    def test_a_failing_wormhole_reports_its_last_stderr_line(self):
        p = self.run_handler("file", header(), WH_RECV_MODE="fail")
        self.assertNotEqual(p.returncode, 0)
        msgs, _ = self.parse(p.stdout)
        self.assertEqual(msgs[-1]["message"], "mailbox is crowded")

    # --- header validation ----------------------------------------------

    def test_a_malformed_code_is_refused_before_wormhole_runs(self):
        for code in ["", "nope", "1-a", "51234-exceed; id",
                     "51234-EXCEED-souvenir", "-1-a-b", "1234567-a-b"]:
            with self.subTest(code=code):
                p = self.run_handler("file", header(code=code))
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(self.commands(), [])

    def test_a_stock_wormhole_code_is_accepted(self):
        """Codes come from the SENDER, who may be running stock wormhole with a
        one-digit nameplate."""
        p = self.run_handler("file", header(code="7-crossover-clockwork"))
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_an_oversized_payload_is_refused(self):
        p = self.run_handler("file", header(size_cap=3),
                             WH_RECV_CONTENT="far too long")
        self.assertNotEqual(p.returncode, 0)
        msgs, _ = self.parse(p.stdout)
        self.assertIn("cap", msgs[-1]["message"])

    def test_the_cap_is_enforced_while_wormhole_writes(self):
        """RLIMIT_FSIZE, not an after-the-fact stat: a sender holding the
        code must not be able to fill the disposable's private volume."""
        p = self.run_handler("file", header(size_cap=3),
                             WH_RECV_CONTENT="x" * 65536)
        self.assertNotEqual(p.returncode, 0)
        msgs, _ = self.parse(p.stdout)
        self.assertIn("cap", msgs[-1]["message"])
        self.assertFalse((self.home / "qvm-wormhole-out").exists())

    def test_non_integer_header_fields_are_refused(self):
        for field, value in [("size_cap", 1.5), ("size_cap", True),
                             ("timeout", True), ("timeout", "60")]:
            with self.subTest(field=field, value=value):
                p = self.run_handler("file", header(**{field: value}))
                self.assertNotEqual(p.returncode, 0)

    def test_an_unterminated_header_does_not_hang(self):
        p = self.run_handler("file", b"{" + b"A" * 20000)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.commands(), [])

    def test_a_hostile_filename_is_reduced_to_a_basename(self):
        p = self.run_handler("file", header(), WH_RECV_NAME="..")
        # ".." cannot be created as a file, so wormhole's shim makes nothing;
        # the point is the handler never interpolates the name into a path.
        self.assertNotEqual(p.returncode, 0)

    def test_the_work_directory_is_removed_afterwards(self):
        for mode in ["file", "text", "fail"]:
            with self.subTest(mode=mode):
                self.run_handler("file", header(), WH_RECV_MODE=mode)
                self.assertFalse((self.home / "qvm-wormhole-out").exists())


    # --- the hold: nothing is handed back until the caller releases it -----

    def release(self, digest):
        return (json.dumps({"release": digest}) + "\n").encode()

    def test_a_held_file_is_reported_then_handed_back_on_release(self):
        sha = hashlib.sha256(b"PAYLOAD").hexdigest()
        p = self.run_handler("file", header(hold=30) + self.release(sha),
                             WH_RECV_NAME="r.pdf", WH_RECV_CONTENT="PAYLOAD")
        self.assertEqual(p.returncode, 0, p.stderr)
        msgs, payload = self.parse(p.stdout)
        self.assertEqual([m["status"] for m in msgs],
                         ["waiting", "held", "payload"])
        self.assertEqual((msgs[1]["name"], msgs[1]["size"], msgs[1]["sha256"]),
                         ("r.pdf", 7, sha))
        self.assertEqual(payload, b"PAYLOAD")

    def test_without_a_matching_release_nothing_is_handed_back(self):
        for tail in [b"", self.release("0" * 64), b"garbage\n",
                     b'{"release": true}\n']:
            with self.subTest(tail=tail):
                p = self.run_handler("file", header(hold=30) + tail,
                                     WH_RECV_CONTENT="SECRET")
                self.assertNotEqual(p.returncode, 0)
                self.assertNotIn(b"SECRET", p.stdout)
                msgs, _ = self.parse(p.stdout)
                self.assertNotIn("payload", [m["status"] for m in msgs])
                self.assertEqual(msgs[-1]["status"], "error")
                self.assertIn("discarded", msgs[-1]["message"])
                self.assertFalse((self.home / "qvm-wormhole-out").exists())

    def test_an_unanswered_hold_times_out_and_discards(self):
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.home),
               "QREXEC_SERVICE_ARGUMENT": "file",
               "QREXEC_REMOTE_DOMAIN": "testvm",
               "WH_TEST_CALLS": str(self.calls),
               "WORMHOLE_RECV_BIN": str(self.shim),
               "WH_RECV_CONTENT": "SECRET"}
        proc = subprocess.Popen([str(HANDLER)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env)
        proc.stdin.write(header(hold=10))
        proc.stdin.flush()          # and stdin stays open: nobody answers
        try:
            proc.wait(timeout=40)   # not communicate(): that closes stdin
            out = proc.stdout.read()
        finally:
            proc.kill()
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn(b"SECRET", out)
        msgs, _ = self.parse(out)
        self.assertIn("not released within 10s", msgs[-1]["message"])
        self.assertFalse((self.home / "qvm-wormhole-out").exists())

    def test_a_bad_hold_is_refused_before_wormhole_runs(self):
        for bad in [0, 9, 4000, True, "30", 1.5]:
            with self.subTest(bad=bad):
                p = self.run_handler("file", header(hold=bad))
                self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.commands(), [])


if __name__ == "__main__":
    unittest.main()
