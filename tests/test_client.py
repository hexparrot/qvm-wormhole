"""Client-side: code minting, config precedence, input refusal, audit hygiene,
and client<->handler integration through a fake qrexec.

Nothing here touches a VM, dom0, or the network.
"""

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLIENT = ROOT / "bin" / "qvm-wormhole"
HANDLER = ROOT / "qrexec" / "wormhole.Send"

# Stands in for qrexec-client-vm: strips the flags, turns "wormhole.Send+file"
# into QREXEC_SERVICE_ARGUMENT, and execs the real handler with our stdin and
# stdout. That gives genuine end-to-end coverage with no dom0 involved.
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

DEAF_QREXEC = """#!/bin/sh
# Accepts the call and exits without reading stdin. The client must not hang.
exit 3
"""

STUCK_QREXEC = """#!/bin/sh
# Accepts the call, never reads stdin, never exits. Only a watchdog that
# covers the STREAMING phase gets the client out of this.
exec sleep 300
"""

CHATTY_QREXEC = """#!/usr/bin/env python3
# Talks before it listens: 256 KiB on stderr, well past the pipe buffer, then
# drains stdin. A client that reads stderr only after exit deadlocks here.
import sys
sys.stderr.write("E" * (256 * 1024)); sys.stderr.flush()
while sys.stdin.buffer.read(65536):
    pass
sys.exit(3)
"""

ESCAPING_QREXEC = """#!/usr/bin/env python3
import sys, json
sys.stdin.buffer.read()
print(json.dumps({"status": "error", "host": "\\x1b]0;x\\x07d",
                  "message": "\\x1b[2Jwiped"}), flush=True)
sys.stderr.write("\\x1b[?1049hraw\\n")
sys.exit(1)
"""

WORMHOLE_SHIM = """#!/bin/sh
exit ${WH_SHIM_RC:-0}
"""


def load(path, name):
    spec = importlib.util.spec_from_loader(
        name, importlib.machinery.SourceFileLoader(name, str(path)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sys.path.insert(0, str(ROOT / "share"))
import qvmwh                                          # noqa: E402
client = load(CLIENT, "qvm_wormhole_client")

# A live approval gate on this machine would put these tests' sends to the real
# approver. Subprocess runs cannot be steered away from it (the path is a
# constant on purpose), so they skip; in-process runs point the constant at a
# path that does not exist.
LIVE_GATE = os.path.lexists(qvmwh.APPROVAL_CONF)
LIVE_GATE_WHY = ("a live approval gate exists at %s; subprocess sends would "
                 "reach its approver" % qvmwh.APPROVAL_CONF)
NO_GATE = str(ROOT / "tests" / "no-such-approval.conf")


class NoLiveGate:
    def setUp(self):
        self._gate = qvmwh.APPROVAL_CONF
        qvmwh.APPROVAL_CONF = NO_GATE
        self.addCleanup(lambda: setattr(qvmwh, "APPROVAL_CONF", self._gate))
        super().setUp()


class WordlistCase(unittest.TestCase):
    def test_the_shipped_wordlist_is_the_real_one(self):
        w = qvmwh.load_wordlist()
        self.assertEqual(len(w["even"]), 256)
        self.assertEqual(len(w["odd"]), 256)
        self.assertEqual(len(set(w["even"])), 256)
        self.assertEqual(w["even"][0], "aardvark")
        self.assertEqual(w["odd"][0], "adroitness")


class CodeCase(unittest.TestCase):
    def setUp(self):
        self.words = qvmwh.load_wordlist()
        src = HANDLER.read_text()
        pattern = src.split("CODE_RE = re.compile(r\"", 1)[1].split("\")", 1)[0]
        self.handler_re = re.compile(pattern)

    def test_minted_codes_satisfy_the_handlers_validator(self):
        """The client and the service must agree on what a code looks like.

        If these drift, every transfer fails at the far end with 'malformed
        code' and the cause is two files apart.
        """
        for _ in range(500):
            self.assertRegex(qvmwh.mint_code(self.words), self.handler_re)

    def test_the_nameplate_is_five_digits(self):
        for _ in range(200):
            n = qvmwh.mint_code(self.words).split("-")[0]
            self.assertEqual(len(n), 5)
            self.assertTrue(10000 <= int(n) <= 99999)

    def test_words_come_from_the_right_lists(self):
        for _ in range(200):
            _, even, odd = qvmwh.mint_code(self.words).split("-")
            self.assertIn(even, [w.lower() for w in self.words["even"]])
            self.assertIn(odd, [w.lower() for w in self.words["odd"]])

    def test_mixed_case_wordlist_entries_are_normalised(self):
        """The code IS the PAKE password, so case must be canonical."""
        allw = self.words["even"] + self.words["odd"]
        self.assertTrue(any(w != w.lower() for w in allw),
                        "wordlist has no capitals; this guard is now vacuous")
        for _ in range(300):
            code = qvmwh.mint_code(self.words)
            self.assertEqual(code, code.lower())

    def test_codes_do_not_repeat(self):
        seen = {qvmwh.mint_code(self.words) for _ in range(500)}
        self.assertGreater(len(seen), 495)


class DvmNameCase(unittest.TestCase):
    def test_only_well_formed_targets_are_accepted(self):
        for good in ["wormhole_dvm", "@dispvm", "@dispvm:wormhole_dvm", "vm-1.2"]:
            self.assertTrue(qvmwh.DVM_RE.match(good), good)

    def test_anything_merely_starting_with_dispvm_is_refused(self):
        """Regression: an unanchored alternation let these through, and dom0
        then refused them with a misleading 'no policy line' diagnosis."""
        for bad in ["@dispvm:wormhole_dvm ", "@dispvm; rm -rf /", "@dispvm:",
                    "dispvm garbage/../", "@dispvm:bad name", "", "-vm",
                    "@anyvm", "a/b"]:
            self.assertIsNone(qvmwh.DVM_RE.match(bad), bad)


class ConfigCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conf = pathlib.Path(self.tmp.name) / "conf"
        self._orig = qvmwh.CONF
        qvmwh.CONF = str(self.conf)
        self.addCleanup(lambda: setattr(qvmwh, "CONF", self._orig))
        for k in list(os.environ):
            if k.startswith("QVM_WORMHOLE_"):
                del os.environ[k]

    def test_precedence_is_defaults_then_conf_then_env(self):
        self.assertEqual(qvmwh.load_conf()["dvm"], "wormhole_dvm")
        self.conf.write_text("dvm = from_conf\n# a comment\ntimeout = 99\n")
        self.assertEqual(qvmwh.load_conf()["dvm"], "from_conf")
        self.assertEqual(qvmwh.load_conf()["timeout"], "99")
        os.environ["QVM_WORMHOLE_DVM"] = "from_env"
        self.addCleanup(os.environ.pop, "QVM_WORMHOLE_DVM", None)
        self.assertEqual(qvmwh.load_conf()["dvm"], "from_env")
        self.assertEqual(qvmwh.load_conf()["timeout"], "99")

    def test_unknown_conf_keys_are_ignored(self):
        self.conf.write_text("nonsense = 1\ndvm = ok_dvm\n")
        c = qvmwh.load_conf()
        self.assertEqual(c["dvm"], "ok_dvm")
        self.assertNotIn("nonsense", c)

    def test_a_malformed_conf_integer_fails_cleanly(self):
        """It used to raise ValueError at argparse-build time, so even --help
        died with a traceback."""
        self.conf.write_text("timeout = 1h\n")
        with self.assertRaises(SystemExit) as cm, \
                contextlib.redirect_stderr(io.StringIO()):
            qvmwh.conf_int(qvmwh.load_conf(), "timeout")
        self.assertEqual(cm.exception.code, 2)


@unittest.skipIf(LIVE_GATE, LIVE_GATE_WHY)
class InputCase(unittest.TestCase):
    def run_client(self, *args, **env_over):
        env = dict(os.environ)
        env["QVM_WORMHOLE_WORDLIST"] = str(ROOT / "share" / "wordlist.txt")
        # Pin the library under test: an installed /usr/share copy would
        # otherwise shadow the repo's.
        env["QVM_WORMHOLE_LIB"] = str(ROOT / "share")
        env.update(env_over)
        return subprocess.run([sys.executable, str(CLIENT), *args],
                              capture_output=True, env=env, timeout=60)

    def test_a_missing_file_is_refused(self):
        self.assertEqual(self.run_client("/nonexistent/nope.txt").returncode, 2)

    def test_an_empty_file_is_refused(self):
        with tempfile.NamedTemporaryFile() as fh:
            p = self.run_client(fh.name)
            self.assertEqual(p.returncode, 2)
            self.assertIn("empty", p.stderr.decode())

    def test_a_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_client(d).returncode, 2)

    def test_oversized_is_refused_against_the_cap(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"x" * 4096)
            name = fh.name
        self.addCleanup(os.unlink, name)
        p = self.run_client(name, "--size-cap", "10")
        self.assertEqual(p.returncode, 2)
        self.assertIn("cap", p.stderr.decode())

    def test_a_bad_dvm_name_is_refused_before_any_call(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"x")
            name = fh.name
        self.addCleanup(os.unlink, name)
        p = self.run_client(name, "--dvm", "@dispvm; rm -rf /")
        self.assertEqual(p.returncode, 2)
        self.assertIn("refusing dvm name", p.stderr.decode())

    def test_a_nonsense_timeout_is_refused(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"x")
            name = fh.name
        self.addCleanup(os.unlink, name)
        for t in ["-100", "0", "999999"]:
            with self.subTest(t=t):
                p = self.run_client(name, "--timeout", t)
                self.assertEqual(p.returncode, 2)

    def test_a_missing_qrexec_binary_fails_cleanly(self):
        """Used to be an uncaught FileNotFoundError with no journal line."""
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"x")
            name = fh.name
        self.addCleanup(os.unlink, name)
        p = self.run_client(name, QVM_WORMHOLE_QREXEC="/nonexistent/qrexec")
        self.assertEqual(p.returncode, 2)
        self.assertIn("cannot run", p.stderr.decode())


@unittest.skipIf(LIVE_GATE, LIVE_GATE_WHY)
class IntegrationCase(unittest.TestCase):
    """Client and handler, wired together through a fake qrexec."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = pathlib.Path(self.tmp.name)
        self.home = self.d / "home"
        self.home.mkdir()
        self.wh = self.write("wormhole", WORMHOLE_SHIM)
        self.src = self.d / "payload.bin"
        self.src.write_bytes(b"A" * (3 * 1024 * 1024))

    def write(self, name, body):
        p = self.d / name
        p.write_text(body)
        p.chmod(0o755)
        return p

    def run_client(self, qrexec_body, *args, **env_over):
        shim = self.write("qrexec", qrexec_body)
        env = dict(os.environ)
        env.update({
            "HOME": str(self.home),
            "QVM_WORMHOLE_WORDLIST": str(ROOT / "share" / "wordlist.txt"),
            "QVM_WORMHOLE_LIB": str(ROOT / "share"),
            "QVM_WORMHOLE_QREXEC": str(shim),
            "FAKE_HANDLER": str(HANDLER),
            "WORMHOLE_SEND_BIN": str(self.wh),
        })
        env.update(env_over)
        return subprocess.run(
            [sys.executable, str(CLIENT), str(self.src), "--timeout", "60",
             *args], capture_output=True, env=env, timeout=120)

    def journal(self):
        jf = self.home / ".local/state/qvm-wormhole/journal.jsonl"
        return json.loads(jf.read_text().splitlines()[-1])

    def test_a_whole_transfer_succeeds(self):
        p = self.run_client(FAKE_QREXEC)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        out = p.stdout.decode()
        self.assertIn("Wormhole code: ", out)
        self.assertIn("wormhole receive ", out)
        self.assertIn("Transfer complete.", out)
        rec = self.journal()
        self.assertEqual(rec["status"], "complete")
        self.assertEqual(rec["sent"], rec["size"])
        self.assertEqual(rec["sha256"],
                         hashlib.sha256(self.src.read_bytes()).hexdigest())

    def test_the_code_is_printed_before_the_transfer_starts(self):
        p = self.run_client(FAKE_QREXEC)
        out = p.stdout.decode()
        self.assertLess(out.index("wormhole receive"), out.index("Sending "))

    def test_a_refusal_is_diagnosed_as_policy(self):
        p = self.run_client(REFUSING_QREXEC)
        self.assertEqual(p.returncode, 126)
        self.assertIn("no policy line", p.stderr.decode())
        self.assertEqual(self.journal()["exit"], 126)

    def test_a_peer_that_floods_stderr_before_reading_does_not_wedge(self):
        """stderr is drained concurrently; a chatty peer must not block the
        write loop, and the run must end well inside the timeout."""
        p = self.run_client(CHATTY_QREXEC)
        self.assertEqual(p.returncode, 3, p.stderr.decode()[-200:])

    def test_terminal_escapes_from_the_far_end_are_neutralised(self):
        p = self.run_client(ESCAPING_QREXEC)
        self.assertNotIn(b"\x1b", p.stdout + p.stderr)
        self.assertIn(b"wiped", p.stderr)

    def test_a_far_end_that_never_reads_does_not_hang(self):
        """The deadlock guard: stdin must always be closed and the process
        reaped, even when the peer vanishes mid-write."""
        p = self.run_client(DEAF_QREXEC)
        self.assertNotEqual(p.returncode, 0)
        self.assertNotEqual(p.returncode, 124, "client waited out the timeout")

    def test_a_failing_wormhole_surfaces_as_a_failed_transfer(self):
        p = self.run_client(FAKE_QREXEC, WH_SHIM_RC="1")
        self.assertEqual(p.returncode, 1)
        self.assertEqual(self.journal()["status"], "error")

    def test_the_journal_records_the_nameplate_not_the_code(self):
        """A full code in a logfile outlives its single use."""
        p = self.run_client(FAKE_QREXEC)
        rec = self.journal()
        self.assertRegex(str(rec["nameplate"]), r"^\d{5}$")
        self.assertNotIn("code", rec)
        code = re.search(r"Wormhole code: (\S+)", p.stdout.decode()).group(1)
        jf = self.home / ".local/state/qvm-wormhole/journal.jsonl"
        self.assertNotIn(code, jf.read_text())


class StreamingWatchdogCase(NoLiveGate, unittest.TestCase):
    """A peer that accepts the call and then never reads stdin used to block
    the write loop forever: proc.wait(timeout) is only reached after the
    loop, so --timeout covered nothing until then."""

    def test_a_peer_stuck_mid_stream_is_shot_with_exit_124(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            src = d / "payload.bin"
            src.write_bytes(b"C" * (4 * 1024 * 1024))   # > any pipe buffer
            shim = d / "qrexec"
            shim.write_text(STUCK_QREXEC)
            shim.chmod(0o755)
            env = {"HOME": str(d)}
            old_env = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            old = (sys.argv, qvmwh.QREXEC, qvmwh.STATE, qvmwh.GRACE)
            sys.argv = ["qvm-wormhole", str(src), "--timeout", "1"]
            qvmwh.QREXEC, qvmwh.STATE, qvmwh.GRACE = str(shim), d / "state", 1
            buf, errbuf = io.StringIO(), io.StringIO()
            started = time.monotonic()
            try:
                with contextlib.redirect_stdout(buf), \
                     contextlib.redirect_stderr(errbuf):
                    rc = client.main()
            finally:
                sys.argv, qvmwh.QREXEC, qvmwh.STATE, qvmwh.GRACE = old
                for k, v in old_env.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            self.assertEqual(rc, 124, errbuf.getvalue())
            self.assertLess(time.monotonic() - started, 20)
            self.assertIn("Gave up", errbuf.getvalue())
            rec = json.loads((d / "state" / "journal.jsonl")
                             .read_text().splitlines()[-1])
            self.assertEqual(rec["exit"], 124)


class ShrinkingFileCase(NoLiveGate, unittest.TestCase):
    """H2 regression, driven in-process so the shrink is deterministic."""

    def test_a_file_that_shrinks_after_hashing_is_reported_honestly(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            src = d / "payload.bin"
            src.write_bytes(b"B" * (2 * 1024 * 1024))
            shim = d / "qrexec"
            shim.write_text(FAKE_QREXEC)
            shim.chmod(0o755)
            wh = d / "wormhole"
            wh.write_text(WORMHOLE_SHIM)
            wh.chmod(0o755)

            orig_measure = qvmwh.measure

            def measure_then_shrink(path):
                size, digest = orig_measure(path)
                os.truncate(path, 4096)     # after stat and hash, before send
                return size, digest

            env = {"HOME": str(d), "FAKE_HANDLER": str(HANDLER),
                   "WORMHOLE_SEND_BIN": str(wh)}
            old_env = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            old = (sys.argv, qvmwh.measure, qvmwh.QREXEC, qvmwh.STATE)
            sys.argv = ["qvm-wormhole", str(src), "--timeout", "60"]
            qvmwh.measure = measure_then_shrink
            qvmwh.QREXEC = str(shim)
            qvmwh.STATE = d / "state"
            buf, errbuf = io.StringIO(), io.StringIO()
            try:
                with contextlib.redirect_stdout(buf), \
                     contextlib.redirect_stderr(errbuf):
                    rc = client.main()
            finally:
                sys.argv, qvmwh.measure, qvmwh.QREXEC, qvmwh.STATE = old
                for k, v in old_env.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v

            self.assertEqual(rc, 1, errbuf.getvalue())
            self.assertIn("changed while sending", errbuf.getvalue())
            self.assertNotIn("no receiver", errbuf.getvalue().lower())
            rec = json.loads(
                (qvmwh.STATE if False else d / "state" / "journal.jsonl")
                .read_text().splitlines()[-1])
            self.assertLess(rec["sent"], rec["size"])


if __name__ == "__main__":
    unittest.main()
