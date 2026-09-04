"""The handler's verb table, header validation and refusal path.

Runs the real handler as a subprocess with a recording shim standing in for
wormhole. Needs no VM and no network.
"""

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HANDLER = ROOT / "qrexec" / "wormhole.Send"
POLICY = ROOT / "qrexec" / "30-wormhole.policy"

SHIM = """#!/bin/sh
printf '%s' "$(basename "$0")" >> "$WH_TEST_CALLS"
for a in "$@"; do printf ' %s' "$a" >> "$WH_TEST_CALLS"; done
printf '\\n' >> "$WH_TEST_CALLS"
[ -n "${WH_SHIM_STDERR:-}" ] && echo "$WH_SHIM_STDERR" >&2
exit "${WH_SHIM_RC:-0}"
"""


def header(payload, **over):
    h = {
        "filename": "report.pdf",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "code": "51234-exceed-souvenir",
        "timeout": 120,
    }
    h.update(over)
    return (json.dumps(h) + "\n").encode()


class HandlerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = pathlib.Path(self.tmp.name)
        self.home = d / "home"
        self.home.mkdir()
        self.calls = d / "calls"
        self.shim = d / "wormhole"
        self.shim.write_text(SHIM)
        self.shim.chmod(0o755)
        self.addCleanup(self.tmp.cleanup)

    def run_handler(self, arg, stdin=b"", **extra):
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.home),
            "QREXEC_SERVICE_ARGUMENT": arg,
            "QREXEC_REMOTE_DOMAIN": "testvm",
            "WH_TEST_CALLS": str(self.calls),
            "WORMHOLE_SEND_BIN": str(self.shim),
        }
        env.update({k: str(v) for k, v in extra.items()})
        return subprocess.run([str(HANDLER)], input=stdin, env=env,
                              capture_output=True, timeout=30)

    def commands(self):
        if not self.calls.exists():
            return []
        return [l for l in self.calls.read_text().splitlines() if l.strip()]

    def statuses(self, proc):
        out = []
        for line in proc.stdout.decode().splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out

    # --- the verb table ------------------------------------------------

    def test_the_file_verb_sends_with_an_exact_argv(self):
        payload = b"hello wormhole\n"
        p = self.run_handler("file", header(payload) + payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.commands()), 1)
        # The whole argv, not a substring: argv[0] and the destination matter.
        argv = self.commands()[0].split()
        self.assertEqual(argv[0], "wormhole")
        self.assertEqual(argv[1:6], ["send", "--code", "51234-exceed-souvenir",
                                     "--no-qr", "--hide-progress"])
        self.assertEqual(len(argv), 7)
        self.assertEqual(argv[6],
                         str(self.home / "qvm-wormhole-in" / "report.pdf"))
        self.assertEqual([s["status"] for s in self.statuses(p)][-1], "complete")

    def test_everything_else_is_refused_and_runs_nothing(self):
        bad = ["", "File", "file;id", "$(id)", "../file", "file file",
               "--help", "text", "dir", "recv"]
        for arg in bad:
            with self.subTest(arg=arg):
                p = self.run_handler(arg, b'{"junk":1}\n')
                self.assertEqual(p.returncode, 2, "arg %r was not refused" % arg)
                self.assertIn("refused", p.stderr.decode())
                self.assertEqual(self.commands(), [],
                                 "arg %r executed something" % arg)

    def test_policy_admits_exactly_the_handler_verbs(self):
        """Guards against the policy and the handler drifting apart."""
        allowed = set()
        for line in POLICY.read_text().splitlines():
            line = line.split("#", 1)[0].split()
            if len(line) >= 5 and line[0] == "wormhole.Send" and line[-1] == "allow":
                allowed.add(line[1].lstrip("+"))
        src = HANDLER.read_text()
        verbs = set(eval(src.split("VERBS = ", 1)[1].split("\n", 1)[0]))
        self.assertEqual(allowed, verbs)

    # --- header validation ---------------------------------------------

    def test_a_filename_cannot_choose_a_path(self):
        """A caller may influence the NAME, never the directory.

        basename() neutralises traversal rather than rejecting it, so
        "../../.bashrc" legitimately becomes ".bashrc" INSIDE the work dir. The
        property under test is containment, not any particular output name.
        """
        payload = b"x" * 32
        work = self.home / "qvm-wormhole-in"
        for name in ["../../.bashrc", "/etc/passwd", "..", ".",
                     "a/b/c.txt", "-rf", "x\ty"]:
            with self.subTest(name=name):
                self.calls.unlink(missing_ok=True)
                p = self.run_handler("file", header(payload, filename=name) + payload)
                self.assertEqual(p.returncode, 0, p.stderr)
                sent = self.commands()[0].rsplit(" ", 1)[1]
                self.assertTrue(sent.startswith(str(work) + os.sep),
                                "%r escaped the work dir: %s" % (name, sent))
                self.assertNotIn(os.sep, sent[len(str(work)) + 1:])
        self.assertFalse((self.home / ".bashrc").exists())
        self.assertFalse((self.home / "a").exists())

    def test_a_malformed_code_is_refused_before_anything_runs(self):
        payload = b"x" * 8
        for code in ["", "nope", "1-a", "51234-exceed-souvenir; id",
                     "51234-EXCEED-souvenir", "-1-a-b"]:
            with self.subTest(code=code):
                p = self.run_handler("file", header(payload, code=code) + payload)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(self.commands(), [])

    def test_a_sha_mismatch_is_caught(self):
        payload = b"x" * 64
        p = self.run_handler("file", header(payload, sha256="0" * 64) + payload)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.commands(), [])

    def test_a_short_payload_is_caught_not_padded(self):
        payload = b"x" * 64
        p = self.run_handler("file", header(payload) + payload[:10])
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.commands(), [])

    def test_exactly_size_bytes_are_read_and_trailing_junk_ignored(self):
        payload = b"y" * 100
        p = self.run_handler("file", header(payload) + payload + b"TRAILING GARBAGE")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.commands()), 1)

    def test_an_oversized_declaration_is_refused(self):
        p = self.run_handler("file", header(b"x", size=99 * 1024**3) + b"x")
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.commands(), [])

    def test_an_unterminated_header_does_not_hang_or_exhaust_memory(self):
        p = self.run_handler("file", b"{" + b"A" * 20000)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.commands(), [])


    def test_a_failing_wormhole_reports_its_last_stderr_line(self):
        payload = b"z" * 16
        p = self.run_handler("file", header(payload) + payload,
                             WH_SHIM_RC=1,
                             WH_SHIM_STDERR="Sending...\nmailbox is crowded")
        self.assertEqual(p.returncode, 1)
        err = [s for s in self.statuses(p) if s["status"] == "error"]
        self.assertEqual(err[-1]["message"], "mailbox is crowded")

    def test_the_payload_is_removed_on_every_path(self):
        """Regression: cleanup used to happen only on the success path."""
        payload = b"q" * 64
        work = self.home / "qvm-wormhole-in"
        cases = [
            ("sha mismatch", header(payload, sha256="0" * 64) + payload, {}),
            ("short payload", header(payload) + payload[:8], {}),
            ("wormhole fails", header(payload) + payload, {"WH_SHIM_RC": 1}),
            ("success", header(payload) + payload, {}),
        ]
        for label, stdin, extra in cases:
            with self.subTest(label):
                self.run_handler("file", stdin, **extra)
                left = [f.name for f in work.iterdir()] if work.exists() else []
                self.assertEqual(left, [], "%s left %r behind" % (label, left))

    def test_non_integer_size_and_timeout_are_refused(self):
        """`size: 64.9` truncating to 64 would desync the byte count."""
        payload = b"w" * 64
        for field, value in [("size", 64.9), ("size", True),
                             ("timeout", True), ("timeout", 12.5)]:
            with self.subTest(field=field, value=value):
                p = self.run_handler("file",
                                     header(payload, **{field: value}) + payload)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(self.commands(), [])

    def test_the_service_cap_is_authoritative(self):
        payload = b"c" * 4096
        p = self.run_handler("file", header(payload) + payload,
                             WORMHOLE_SEND_SIZE_CAP=100)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.commands(), [])


if __name__ == "__main__":
    unittest.main()
