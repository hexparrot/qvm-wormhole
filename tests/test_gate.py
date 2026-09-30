"""The optional approval gate (approval-hook v1) on the send client.

Everything runs in-process against a gate file in a temporary directory: the
gate's path and the owner uid it demands are module constants that only an
in-process test can move. Nothing here touches the real gate path, a VM, dom0
or the network; the far end is the real wormhole.Send handler behind a fake
qrexec, as in test_client.
"""

import contextlib
import hashlib
import io
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from tests.test_client import (CLIENT, FAKE_QREXEC, HANDLER, ROOT,
                               WORMHOLE_SHIM, client, qvmwh)

MARK_QREXEC = """#!/bin/sh
: > "%s"
exit 1
"""

# A stub approver. Its environment is only PATH, so everything it needs is
# baked into its text. It records the request and its initial environment.
APPROVER = r'''#!%(py)s
import json, os, signal, sys, time
rec = %(rec)r
mode = %(mode)r
def term(*_):
    open(rec + ".term", "w").write("TERM")
    sys.exit(3)
signal.signal(signal.SIGTERM, term)
line = sys.stdin.readline()
req = json.loads(line)
env = dict(kv.split("=", 1) for kv in
           open("/proc/self/environ", "rb").read().decode().split("\0") if "=" in kv)
json.dump({"request": req, "env": env}, open(rec, "w"))
reply = {"v": 1, "id": req["id"], "digest": req["digest"],
         "decision": "approve", "reason": "ok"}
if mode == "deny":
    reply["decision"] = "deny"; reply["reason"] = "owner said no"
elif mode == "wrong_id":
    reply["id"] = "0" * 32
elif mode == "wrong_digest":
    reply["digest"] = "sha256:" + "0" * 64
elif mode == "v2":
    reply["v"] = 2
elif mode == "no_decision":
    reply["decision"] = "maybe"
elif mode == "exit1":
    print(json.dumps(reply)); sys.exit(1)
elif mode == "badjson":
    print("{not json"); sys.exit(0)
elif mode == "two_lines":
    print(json.dumps(reply)); print(json.dumps(reply)); sys.exit(0)
elif mode == "no_newline":
    sys.stdout.write(json.dumps(reply)); sys.exit(0)
elif mode == "oversize":
    reply["reason"] = "x" * 9000
elif mode == "hang":
    time.sleep(300)
print(json.dumps(reply))
'''


class GateBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = pathlib.Path(self.tmp.name)
        os.chmod(self.d, 0o755)
        self.gdir = self.d / "approval.d"
        self.gdir.mkdir(mode=0o755)
        os.chmod(self.gdir, 0o755)
        self.conf = self.gdir / "50-oci.conf"
        self.rec = self.d / "approver-record.json"
        self.state = self.d / "state"
        self.src = self.d / "payload.bin"
        self.src.write_bytes(os.urandom(300 * 1024) + b"end")
        self.wh = self.exe("wormhole", WORMHOLE_SHIM)
        self.qrexec = self.exe("qrexec", FAKE_QREXEC)
        self.marker = self.d / "qrexec-was-called"
        saved = {k: getattr(qvmwh, k) for k in (
            "APPROVAL_CONF", "ROOT_UID", "QREXEC", "QREXEC_DEFAULT", "STATE",
            "APPROVER_TIMEOUT_RANGE", "APPROVER_EXTRA_WAIT",
            "APPROVER_KILL_GRACE", "rehash")}
        self.addCleanup(lambda: [setattr(qvmwh, k, v) for k, v in saved.items()])
        qvmwh.APPROVAL_CONF = str(self.conf)
        qvmwh.ROOT_UID = os.getuid()
        qvmwh.QREXEC = None
        qvmwh.QREXEC_DEFAULT = str(self.qrexec)
        qvmwh.STATE = self.state
        env = {"FAKE_HANDLER": str(HANDLER), "WORMHOLE_SEND_BIN": str(self.wh)}
        self._old_env = {k: os.environ.get(k) for k in list(env) + [
            "HOME", "QVM_WORMHOLE_QREXEC", "QVM_WORMHOLE_WORDLIST",
            "QVM_WORMHOLE_LIB"]}
        self.addCleanup(self._restore_env)
        for k in ("QVM_WORMHOLE_QREXEC", "QVM_WORMHOLE_WORDLIST", "QVM_WORMHOLE_LIB"):
            os.environ.pop(k, None)
        os.environ.update(env)

    def _restore_env(self):
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def exe(self, name, body, mode=0o755):
        p = self.d / name
        p.write_text(body)
        os.chmod(p, mode)
        return p

    def approver(self, mode="approve", name="approver"):
        return self.exe(name, APPROVER % {"py": sys.executable,
                                          "rec": str(self.rec), "mode": mode})

    def gate(self, text=None, mode="approve", timeout=None):
        if text is None:
            a = self.approver(mode)
            text = "approver = %s\n" % a
            if timeout is not None:
                text += "approver_timeout = %s\n" % timeout
            text += "actions = wormhole.send\n"
        self.conf.write_text(text)
        os.chmod(self.conf, 0o644)

    def run_main(self, *args):
        old = sys.argv
        sys.argv = ["qvm-wormhole", *args]
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    rc = client.main()
                except SystemExit as e:
                    rc = e.code
        finally:
            sys.argv = old
        return rc, out.getvalue(), err.getvalue()

    def send(self, *extra):
        return self.run_main(str(self.src), "--timeout", "60", *extra)

    def journal(self):
        return json.loads((self.state / "journal.jsonl").read_text()
                          .splitlines()[-1])

    def request(self):
        return json.loads(self.rec.read_text())

    def assertNoStaging(self):
        self.assertEqual(list(self.state.glob("stage-*")), [])


class ContractConstantCase(unittest.TestCase):
    def test_bin_and_library_name_the_same_gate_path(self):
        lit = re.search(r'_APPROVAL_CONF = "([^"]+)"', CLIENT.read_text()).group(1)
        self.assertEqual(lit, qvmwh.APPROVAL_CONF)
        self.assertEqual(lit, "/usr/local/etc/approval.d/50-oci.conf")

    def test_canonical_form_is_pinned(self):
        self.assertEqual(qvmwh.canon({"b": [1, "é"], "a": {"d": 1, "c": None}}),
                         b'{"a":{"c":null,"d":1},"b":[1,"\\u00e9"]}')


class UngatedCase(GateBase):
    def test_absent_gate_sends_as_before_with_no_approver(self):
        rc, out, err = self.send()
        self.assertEqual(rc, 0, err)
        self.assertIn("Wormhole code: ", out)
        self.assertFalse(self.rec.exists())
        j = self.journal()
        self.assertEqual(j["approval"], "none")
        self.assertEqual(j["v"], 1)

    def test_ungated_env_overrides_still_apply(self):
        os.environ["QVM_WORMHOLE_QREXEC"] = "/nonexistent/qrexec"
        rc, _, err = self.send()
        self.assertEqual(rc, 2)
        self.assertIn("/nonexistent/qrexec", err)

    def test_fd_works_ungated(self):
        fd = os.open(self.src, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        rc, out, err = self.run_main("--fd", str(fd), "--timeout", "60")
        self.assertEqual(rc, 0, err)
        j = self.journal()
        self.assertEqual(j["path"], str(self.src))
        self.assertEqual(j["sha256"], hashlib.sha256(self.src.read_bytes()).hexdigest())
        self.assertNoStaging()

    def test_file_and_fd_are_exclusive(self):
        self.assertEqual(self.run_main(str(self.src), "--fd", "0")[0], 2)
        self.assertEqual(self.run_main("--timeout", "5")[0], 2)


class ContractFlagCase(GateBase):
    def contract(self):
        rc, out, _ = self.run_main("--contract")
        self.assertEqual(rc, 0)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 1)
        return json.loads(lines[0])

    def test_absent(self):
        c = self.contract()
        self.assertEqual((c["cli"], c["approval_hook"], c["gated"], c["approver"],
                          c["approver_ok"], c["error"]), (1, 1, False, None, False, None))
        self.assertEqual(c["conf"], str(self.conf))
        self.assertIn("dvm", c)
        self.assertIsInstance(c["size_cap"], int)

    def test_present_and_good_never_runs_the_approver(self):
        self.gate()
        c = self.contract()
        self.assertTrue(c["gated"] and c["approver_ok"])
        self.assertEqual(c["approver"], str(self.d / "approver"))
        self.assertIsNone(c["error"])
        self.assertFalse(self.rec.exists())

    def test_present_and_broken(self):
        self.gate("approver = /nonexistent/approver\n")
        c = self.contract()
        self.assertTrue(c["gated"])
        self.assertFalse(c["approver_ok"])
        self.assertIn("nonexistent", c["error"])


class ApprovedCase(GateBase):
    def test_approve_sends_the_staged_bytes_after_asking(self):
        self.gate()
        rc, out, err = self.send()
        self.assertEqual(rc, 0, err)
        req = self.request()["request"]
        want = hashlib.sha256(self.src.read_bytes()).hexdigest()
        self.assertEqual(req["subject"]["file"]["sha256"], want)
        self.assertEqual(req["subject"]["file"]["size"], self.src.stat().st_size)
        self.assertEqual(req["subject"]["file"]["path"], str(self.src))
        self.assertEqual(req["subject"]["file"]["name"], "payload.bin")
        self.assertEqual(req["targets"], ["@dispvm:wormhole_dvm"])
        self.assertEqual((req["v"], req["type"], req["action"], req["shape"], req["provider"]),
                         (1, "request", "wormhole.send", "content-out", "qvm-wormhole"))
        self.assertRegex(req["id"], r"^[0-9a-f]{32}$")
        self.assertEqual(req["digest"], qvmwh.request_digest(
            req["action"], req["shape"], req["subject"], req["targets"]))
        self.assertEqual(req["requester"], "qvm-wormhole command line")
        self.assertEqual(req["wait_s"], 420)
        j = self.journal()
        self.assertEqual(j["approval"], "approved")
        self.assertEqual(j["sha256"], want)
        self.assertEqual(j["status"], "complete")    # the handler checked the bytes
        self.assertLess(out.index("Approved."), out.index("Wormhole code: "))
        self.assertNoStaging()

    def test_the_approver_sees_only_path(self):
        self.gate()
        os.environ["HOME"] = str(self.d / "hostile-home")
        rc, _, err = self.send()
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.request()["env"], {"PATH": "/usr/bin:/bin"})

    def test_hostile_env_is_ignored_while_gated(self):
        self.gate()
        bad = self.d / "bad-words.txt"
        bad.write_text("[even]\n" + "zzeven\n" * 16 + "[odd]\n" + "zzodd\n" * 16)
        os.environ["QVM_WORMHOLE_WORDLIST"] = str(bad)
        os.environ["QVM_WORMHOLE_QREXEC"] = "/nonexistent/qrexec"
        rc, out, err = self.send()
        self.assertEqual(rc, 0, err)
        code = re.search(r"Wormhole code: (\S+)", out).group(1)
        self.assertNotIn("zz", code)

    def test_json_events_in_order_and_nothing_else_on_stdout(self):
        self.gate()
        rc, out, err = self.send("--json", "--requester", "agent test")
        self.assertEqual(rc, 0, err)
        events = [json.loads(line) for line in out.splitlines()]
        kinds = [e["event"] for e in events]
        self.assertEqual(kinds[:3], ["staged", "approval", "code"])
        self.assertEqual(kinds[-1], "done")
        self.assertEqual(events[1]["decision"], "approve")
        self.assertEqual(events[-1]["exit"], 0)
        self.assertIn("status", kinds)
        self.assertRegex(events[2]["nameplate"], r"^\d{5}$")
        self.assertTrue(events[2]["code"].startswith(events[2]["nameplate"] + "-"))
        self.assertIn("Wormhole code:", err)
        self.assertEqual(self.request()["request"]["requester"], "agent test")

    def test_approver_wait_can_only_shorten(self):
        self.gate(timeout=20)
        self.send("--approver-wait", "300")
        self.assertEqual(self.request()["request"]["wait_s"], 20)
        self.send("--approver-wait", "12")
        self.assertEqual(self.request()["request"]["wait_s"], 12)
        self.assertEqual(self.send("--approver-wait", "5")[0], 2)

    def test_gated_fd(self):
        self.gate()
        fd = os.open(self.src, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        rc, _, err = self.run_main("--fd", str(fd), "--timeout", "60")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.request()["request"]["subject"]["file"]["path"], str(self.src))

    def test_bad_requester_is_refused(self):
        self.gate()
        self.assertEqual(self.send("--requester", "x" * 121)[0], 2)
        self.assertEqual(self.send("--requester", "a\x1bb")[0], 2)


class RefusedCase(GateBase):
    def refused(self, why_re=None, **kw):
        self.exe("qrexec", MARK_QREXEC % self.marker)
        rc, out, err = self.send(**kw) if kw else self.send()
        self.assertEqual(rc, 125, err)
        self.assertNotIn("Wormhole code", out + err)
        self.assertFalse(self.marker.exists(), "qrexec was called")
        self.assertEqual(self.journal()["exit"], 125)
        if why_re:
            self.assertRegex(err, why_re)
        self.assertNoStaging()
        return self.journal()

    def test_deny(self):
        self.gate(mode="deny")
        self.assertEqual(self.refused("owner said no")["approval"], "denied")

    def test_contract_breaking_replies(self):
        for mode in ("wrong_id", "wrong_digest", "v2", "no_decision", "exit1",
                     "badjson", "two_lines", "no_newline", "oversize"):
            with self.subTest(mode=mode):
                self.gate(mode=mode)
                self.assertTrue(self.refused()["approval"].startswith("error:"))

    def test_broken_gates(self):
        good = self.approver()
        cases = {
            "missing approver": "approver = %s\n" % (self.d / "nope"),
            "no approver line": "actions = wormhole.send\n",
            "relative approver": "approver = approver\n",
            "duplicate key": "approver = %s\napprover = %s\n" % (good, good),
            "timeout too small": "approver = %s\napprover_timeout = 5\n" % good,
            "timeout too big": "approver = %s\napprover_timeout = 99999\n" % good,
            "timeout not a number": "approver = %s\napprover_timeout = 1h\n" % good,
            "not key=value": "approver %s\n" % good,
        }
        for why, text in cases.items():
            with self.subTest(why=why):
                self.gate(text)
                j = self.refused("broken")
                self.assertTrue(j["approval"].startswith("error:"))
                self.assertFalse(self.rec.exists())

    def test_unsafe_modes_and_owners(self):
        a = self.approver()
        text = "approver = %s\n" % a
        for what, fix in (
                ("writable approver", lambda: os.chmod(a, 0o777)),
                ("unexecutable approver", lambda: os.chmod(a, 0o644)),
                ("writable conf", lambda: os.chmod(self.conf, 0o666)),
                ("writable dir", lambda: os.chmod(self.gdir, 0o777)),
                ("wrong owner", lambda: setattr(qvmwh, "ROOT_UID", os.getuid() + 1))):
            with self.subTest(what=what):
                self.gate(text)
                os.chmod(a, 0o755)
                os.chmod(self.gdir, 0o755)
                qvmwh.ROOT_UID = os.getuid()
                fix()
                self.refused("broken")
                os.chmod(a, 0o755)
                os.chmod(self.gdir, 0o755)
                qvmwh.ROOT_UID = os.getuid()

    def test_a_symlinked_or_dangling_gate_is_present_and_broken(self):
        real = self.d / "real.conf"
        real.write_text("approver = %s\n" % self.approver())
        os.symlink(real, self.conf)
        self.refused("broken")
        os.unlink(self.conf)
        os.symlink(self.d / "nothing-here", self.conf)
        self.refused("broken")

    def test_a_changed_staged_copy_is_not_sent(self):
        self.gate()
        qvmwh.rehash = lambda fd: (1, "0" * 64)
        j = self.refused("changed after approval")
        self.assertEqual(j["approval"], "error:content-changed")

    def test_a_hung_approver_is_stopped(self):
        qvmwh.APPROVER_TIMEOUT_RANGE = (1, 3600)
        qvmwh.APPROVER_EXTRA_WAIT = 1
        qvmwh.APPROVER_KILL_GRACE = 2
        self.gate(mode="hang", timeout=1)
        t0 = time.monotonic()
        j = self.refused("in time")
        self.assertLess(time.monotonic() - t0, 15)
        self.assertTrue(pathlib.Path(str(self.rec) + ".term").exists())
        self.assertTrue(j["approval"].startswith("error:"))


class CancelCase(GateBase):
    def test_ctrl_c_while_waiting_stops_the_approver(self):
        self.exe("qrexec", MARK_QREXEC % self.marker)
        self.gate(mode="hang", timeout=60)
        me = os.getpid()
        threading.Timer(1.5, lambda: os.kill(me, signal.SIGINT)).start()
        rc, out, err = self.send()
        self.assertEqual(rc, 130, err)
        deadline = time.monotonic() + 5
        term = pathlib.Path(str(self.rec) + ".term")
        while not term.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertTrue(term.exists(), "the approver was not sent SIGTERM")
        self.assertFalse(self.marker.exists())
        j = self.journal()
        self.assertEqual((j["exit"], j["approval"]), (130, "error:cancelled"))
        self.assertNoStaging()


class LibraryPathCase(unittest.TestCase):
    """While the gate is on, QVM_WORMHOLE_LIB is not consulted. The bin's own
    literal decides, so a copy of the bin with that literal moved stands in."""

    def run_copy(self, gate_present):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "bin").mkdir()
            os.symlink(ROOT / "share", d / "share")
            gate = d / "gate.conf"
            if gate_present:
                gate.write_text("approver = /nonexistent\n")
            src = CLIENT.read_text().replace(
                '_APPROVAL_CONF = "/usr/local/etc/approval.d/50-oci.conf"',
                '_APPROVAL_CONF = %r' % str(gate))
            (d / "bin" / "qvm-wormhole").write_text(src)
            hostile = d / "hostile"
            hostile.mkdir()
            (hostile / "qvmwh.py").write_text("import sys; print('HOSTILE'); sys.exit(99)\n")
            env = dict(os.environ, QVM_WORMHOLE_LIB=str(hostile))
            return subprocess.run([sys.executable, str(d / "bin" / "qvm-wormhole"), "--contract"],
                                  capture_output=True, text=True, env=env, timeout=30)

    def test_lib_env_ignored_when_gated(self):
        p = self.run_copy(True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("HOSTILE", p.stdout)
        json.loads(p.stdout)

    def test_lib_env_honoured_when_not_gated(self):
        p = self.run_copy(False)
        self.assertEqual(p.returncode, 99)
        self.assertIn("HOSTILE", p.stdout)


if __name__ == "__main__":
    unittest.main()
