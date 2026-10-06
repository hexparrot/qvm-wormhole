"""qvm-wormhole-recv: code handling, the hold, payload framing, the optional
approval gate, and what it refuses to write. Nothing here touches a VM, dom0,
the network, or the real approval gate.

Every run is IN-PROCESS: the gate's path and owner uid are module constants
that only an in-process test can move, and a subprocess run on a machine with a
live gate would put a test offer to the real approver.

The happy path runs the REAL handler behind a fake qrexec. The hostile cases use
crafted services, because the point is that the client does not trust the
service's declared name, size or digest -- nor that it held what it sends.
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
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLIENT = ROOT / "bin" / "qvm-wormhole-recv"
HANDLER = ROOT / "qrexec" / "wormhole.Recv"
sys.path.insert(0, str(ROOT / "share"))
import qvmwh  # noqa: E402


def load(path, name):
    spec = importlib.util.spec_from_loader(
        name, importlib.machinery.SourceFileLoader(name, str(path)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


recv = load(CLIENT, "qvm_wormhole_recv_client")

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

MARK_QREXEC = """#!/bin/sh
: > "%s"
exit 1
"""

WORMHOLE_SHIM = """#!/bin/sh
printf '%s' "${WH_RECV_CONTENT:-hello}" > "${WH_RECV_NAME:-got.txt}"
exit 0
"""


def service(name="ok.txt", declared=None, body=b"data", sha=None, hold=True,
            payload_over=None, record=None):
    """A service that lies about the payload in the ways that matter. With
    hold, it speaks the hold protocol (held, then a release line, then the
    payload); `payload_over` makes the payload header differ from the held
    one; `record` saves the release line it got."""
    return """#!/usr/bin/env python3
import sys, json, hashlib
fd = sys.stdin.buffer
fd.readline()
body = %r
head = {"status": "held", "host": "disp0", "name": %r,
        "size": %s, "sha256": %r}
if %r:
    sys.stdout.write(json.dumps(head) + "\\n")
    sys.stdout.flush()
    rel = fd.readline()
    if %r:
        open(%r, "wb").write(rel)
    if not rel:
        sys.exit(1)
head["status"] = "payload"
head.update(%r)
sys.stdout.write(json.dumps(head) + "\\n")
sys.stdout.flush()
sys.stdout.buffer.write(body)
sys.stdout.buffer.flush()
""" % (body, name,
       len(body) if declared is None else declared,
       sha if sha is not None else hashlib.sha256(body).hexdigest(),
       hold, bool(record), str(record or ""), payload_over or {})


SLOW_EVIL_SERVICE = """#!/usr/bin/env python3
# Declares an absurd size, then stalls. The client must refuse AND return
# promptly, not sit out a 30s wait on a peer it has already given up on.
import sys, json, time
sys.stdin.buffer.readline()
print(json.dumps({"status": "held", "host": "d", "name": "x",
                  "size": 10**9, "sha256": "0" * 64}), flush=True)
time.sleep(120)
"""

LONG_LINE_SERVICE = """#!/usr/bin/env python3
import sys
sys.stdin.buffer.readline()
sys.stdout.write("{" + "A" * 20000)
sys.stdout.flush()
"""

ESCAPING_SERVICE = """#!/usr/bin/env python3
import sys, json
sys.stdin.buffer.readline()
print(json.dumps({"status": "waiting", "host": "\\x1b]0;x\\x07disp0"}), flush=True)
print(json.dumps({"status": "error", "message": "\\x1b[2Jwiped"}), flush=True)
sys.stderr.write("\\x1b[?1049hraw\\n")
sys.exit(1)
"""

# A stub approver. Its environment is only PATH, so everything it needs is
# baked into its text. It records the request and its initial environment.
APPROVER = r'''#!%(py)s
import json, sys, time
rec = %(rec)r
mode = %(mode)r
req = json.loads(sys.stdin.readline())
env = dict(kv.split("=", 1) for kv in
           open("/proc/self/environ", "rb").read().decode().split("\0") if "=" in kv)
json.dump({"request": req, "env": env}, open(rec, "w"))
reply = {"v": 1, "id": req["id"], "digest": req["digest"],
         "decision": "approve", "reason": "ok"}
if mode == "deny":
    reply["decision"] = "deny"; reply["reason"] = "owner said no"
elif mode == "wrong_digest":
    reply["digest"] = "sha256:" + "0" * 64
elif mode == "hang":
    time.sleep(300)
print(json.dumps(reply))
'''


class RecvBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = pathlib.Path(self.tmp.name)
        os.chmod(self.d, 0o755)
        self.home = self.d / "home"
        self.home.mkdir()
        self.dest = self.home / "WormIncoming"
        self.state = self.home / ".local/state/qvm-wormhole"
        self.gdir = self.d / "approval.d"
        self.gdir.mkdir(mode=0o755)
        os.chmod(self.gdir, 0o755)
        self.conf = self.gdir / "50-oci.conf"
        self.rec = self.d / "approver-record.json"
        self.qrexec = self.exe("qrexec", FAKE_QREXEC)
        self.wh = self.exe("wormhole", WORMHOLE_SHIM)
        saved = {k: getattr(qvmwh, k) for k in (
            "APPROVAL_CONF", "ROOT_UID", "QREXEC", "QREXEC_DEFAULT", "STATE")}
        self.addCleanup(lambda: [setattr(qvmwh, k, v) for k, v in saved.items()])
        qvmwh.APPROVAL_CONF = str(self.conf)          # absent unless gate()
        qvmwh.ROOT_UID = os.getuid()
        qvmwh.QREXEC = None
        qvmwh.QREXEC_DEFAULT = str(self.qrexec)
        qvmwh.STATE = self.state
        keys = ["HOME", "DISPLAY", "FAKE_HANDLER", "WORMHOLE_RECV_BIN",
                "WH_RECV_NAME", "WH_RECV_CONTENT", "QVM_WORMHOLE_QREXEC",
                "QVM_WORMHOLE_LIB", "QVM_WORMHOLE_DVM", "QVM_WORMHOLE_TIMEOUT",
                "QVM_WORMHOLE_SIZE_CAP"]
        old = {k: os.environ.get(k) for k in keys}
        self.addCleanup(lambda: [os.environ.pop(k, None) if v is None
                                 else os.environ.__setitem__(k, v)
                                 for k, v in old.items()])
        for k in keys:
            os.environ.pop(k, None)
        os.environ.update({"HOME": str(self.home), "DISPLAY": "",
                           "FAKE_HANDLER": str(HANDLER),
                           "WORMHOLE_RECV_BIN": str(self.wh)})

    def exe(self, name, body, mode=0o755):
        p = self.d / name
        p.write_text(body)
        os.chmod(p, mode)
        return p

    def gate(self, mode="approve", text=None):
        if text is None:
            a = self.exe("approver", APPROVER % {
                "py": sys.executable, "rec": str(self.rec), "mode": mode})
            text = "approver = %s\napprover_timeout = 10\n" % a
        self.conf.write_text(text)
        os.chmod(self.conf, 0o644)

    def run_client(self, *args, service=None, qrexec=None, **env):
        if service is not None:
            os.environ["FAKE_HANDLER"] = str(self.exe("svc", service))
        if qrexec is not None:
            qvmwh.QREXEC_DEFAULT = str(self.exe("qrexec-alt", qrexec))
        os.environ.update({k: str(v) for k, v in env.items()})
        old_argv, old_in = sys.argv, sys.stdin
        sys.argv, sys.stdin = ["qvm-wormhole-recv", *args], io.StringIO()
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    rc = recv.main()
                except SystemExit as e:
                    rc = e.code
        finally:
            sys.argv, sys.stdin = old_argv, old_in
        return rc, out.getvalue(), err.getvalue()

    def landed(self):
        return sorted(p.name for p in self.dest.iterdir()) if self.dest.exists() else []

    def journal(self):
        return json.loads((self.state / "journal.jsonl").read_text()
                          .splitlines()[-1])

    def request(self):
        return json.loads(self.rec.read_text())


class RecvClientCase(RecvBase):
    # --- the destination ---------------------------------------------------

    def test_the_destination_is_fixed_to_wormincoming(self):
        self.assertEqual(recv.DEST, "~/WormIncoming")
        rc, _, err = self.run_client("--output-dir", str(self.d), "7-a-b")
        self.assertEqual(rc, 2, "an --output-dir option must not exist")
        self.assertIn("unrecognized arguments", err)

    def test_contract_reports_the_destination_and_no_gate(self):
        rc, out, _ = self.run_client("--contract")
        self.assertEqual(rc, 0)
        c = json.loads(out)
        self.assertEqual(c["dest"], str(self.dest))
        self.assertEqual((c["cli"], c["approval_hook"], c["gated"], c["hold"]),
                         (1, 1, False, True))

    # --- code handling -----------------------------------------------------

    def test_a_malformed_code_is_refused_before_any_call(self):
        for code in ["nope", "1-a", "51234-exceed; id", "", "../../x"]:
            with self.subTest(code=code):
                rc, _, _ = self.run_client(code)
                self.assertEqual(rc, 2)
                self.assertEqual(self.landed(), [])

    def test_a_stock_wormhole_code_is_accepted(self):
        rc, _, err = self.run_client("7-crossover-clockwork")
        self.assertEqual(rc, 0, err)

    def test_an_uppercase_code_is_normalised(self):
        """Codes are case-sensitive to the PAKE; a human retyping one should not
        be defeated by shift."""
        rc, _, err = self.run_client("7-CROSSOVER-Clockwork")
        self.assertEqual(rc, 0, err)

    def test_with_no_code_and_no_way_to_ask_it_fails_cleanly(self):
        rc, _, err = self.run_client()
        self.assertEqual(rc, 2)
        self.assertIn("no way to ask", err)

    # --- the happy path, through the real handler --------------------------

    def test_a_whole_receive_lands_the_file(self):
        rc, _, err = self.run_client("51234-exceed-souvenir",
                                     WH_RECV_NAME="report.pdf",
                                     WH_RECV_CONTENT="PAYLOAD")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.landed(), ["report.pdf"])
        got = self.dest / "report.pdf"
        self.assertEqual(got.read_bytes(), b"PAYLOAD")
        self.assertEqual(oct(got.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(self.dest.stat().st_mode & 0o777), "0o700")
        self.assertEqual(self.journal()["approval"], "none")

    def test_json_events_in_order_and_nothing_else_on_stdout(self):
        rc, out, err = self.run_client("--json", "51234-exceed-souvenir",
                                       WH_RECV_CONTENT="PAYLOAD")
        self.assertEqual(rc, 0, err)
        evs = [json.loads(line) for line in out.splitlines()]
        self.assertEqual([e["event"] for e in evs],
                         ["waiting", "offer", "approval", "received", "done"])
        self.assertEqual(evs[1]["sha256"], hashlib.sha256(b"PAYLOAD").hexdigest())
        self.assertEqual(evs[2]["decision"], "none")
        self.assertEqual(evs[3]["path"], str(self.dest / "got.txt"))
        self.assertEqual(evs[-1]["exit"], 0)

    def test_a_second_transfer_does_not_clobber_the_first(self):
        self.run_client("51234-exceed-souvenir",
                        WH_RECV_NAME="a.txt", WH_RECV_CONTENT="first")
        self.run_client("51234-exceed-souvenir",
                        WH_RECV_NAME="a.txt", WH_RECV_CONTENT="second")
        self.assertEqual(self.landed(), ["a.1.txt", "a.txt"])
        self.assertEqual((self.dest / "a.txt").read_bytes(), b"first")

    def test_the_journal_records_the_nameplate_not_the_code(self):
        self.run_client("51234-exceed-souvenir")
        text = (self.state / "journal.jsonl").read_text()
        rec = self.journal()
        self.assertEqual(rec["direction"], "recv")
        self.assertEqual(rec["nameplate"], "51234")
        self.assertEqual(rec["v"], 1)
        self.assertNotIn("exceed-souvenir", text)

    # --- not trusting the service -------------------------------------------

    def test_a_service_supplied_path_cannot_escape_the_output_dir(self):
        """The name originates with the REMOTE SENDER, so this end re-sanitises
        it even though our own service already did."""
        for name in ["../../.bashrc", "/etc/passwd", "..", "a/b/c", "-rf",
                     "evil‮txt.exe", "bell\x07"]:
            with self.subTest(name=name):
                rc, _, err = self.run_client("51234-exceed-souvenir",
                                             service=service(name=name))
                self.assertEqual(rc, 0, err)
                for f in self.dest.iterdir():
                    self.assertNotIn("/", f.name)
                    self.assertTrue(f.name.isprintable(), repr(f.name))
        self.assertFalse((self.home / ".bashrc").exists())
        self.assertFalse((self.home / "a").exists())

    def test_the_release_names_exactly_the_held_digest(self):
        rel = self.d / "release.line"
        rc, _, err = self.run_client("51234-exceed-souvenir",
                                     service=service(record=rel))
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(rel.read_bytes()),
                         {"release": hashlib.sha256(b"data").hexdigest()})

    def test_a_payload_that_was_never_held_is_refused(self):
        """An older handler (or a hostile one) that skips the hold would
        stream bytes nobody looked at."""
        rc, _, err = self.run_client("51234-exceed-souvenir",
                                     service=service(hold=False))
        self.assertEqual(rc, 2)
        self.assertIn("had not held", err)
        self.assertEqual(self.landed(), [])

    def test_a_payload_that_differs_from_the_offer_is_refused(self):
        for over in [{"name": "other.txt"}, {"size": 3},
                     {"sha256": "1" * 64}]:
            with self.subTest(over=over):
                rc, _, err = self.run_client(
                    "51234-exceed-souvenir", service=service(payload_over=over))
                self.assertEqual(rc, 2)
                self.assertIn("not the file that was offered", err)
                self.assertEqual(self.landed(), [])

    def test_a_truncated_payload_leaves_nothing_behind(self):
        rc, _, _ = self.run_client(
            "51234-exceed-souvenir",
            service=service(declared=1000, body=b"short"))
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.landed(), [], "a partial file was left in place")

    def test_a_bad_digest_discards_the_file(self):
        rc, _, err = self.run_client("51234-exceed-souvenir",
                                     service=service(sha="0" * 64))
        self.assertNotEqual(rc, 0)
        self.assertIn("mismatch", err)
        self.assertEqual(self.landed(), [])

    def test_a_malformed_digest_is_refused_at_the_offer(self):
        rc, _, err = self.run_client("51234-exceed-souvenir",
                                     service=service(sha="ZZ"))
        self.assertEqual(rc, 2)
        self.assertIn("sha256", err)
        self.assertEqual(self.landed(), [])

    def test_an_oversized_declaration_is_refused_before_reading(self):
        rc, _, _ = self.run_client(
            "51234-exceed-souvenir", "--size-cap", "4",
            service=service(body=b"much longer than four"))
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.landed(), [])

    def test_a_nonsense_declared_size_is_refused(self):
        for bad in ["0", "-5", "true"]:
            with self.subTest(bad=bad):
                rc, _, _ = self.run_client(
                    "51234-exceed-souvenir", service=service(declared=bad))
                self.assertNotEqual(rc, 0)
                self.assertEqual(self.landed(), [])

    def test_a_failed_receive_is_journalled(self):
        """The audit exists for exactly this event."""
        rc, _, _ = self.run_client("51234-exceed-souvenir",
                                   service=service(sha="0" * 64))
        self.assertEqual(rc, 2)
        rec = self.journal()
        self.assertEqual(rec["exit"], 2)
        self.assertIn("mismatch", rec["error"])
        self.assertIsNone(rec["path"])

    def test_an_early_refusal_returns_promptly(self):
        started = time.monotonic()
        rc, _, _ = self.run_client("51234-exceed-souvenir", "--size-cap", "100",
                                   service=SLOW_EVIL_SERVICE)
        self.assertEqual(rc, 2)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(self.landed(), [])

    def test_an_overlong_status_line_is_a_clean_error(self):
        started = time.monotonic()
        rc, _, err = self.run_client("51234-exceed-souvenir",
                                     service=LONG_LINE_SERVICE)
        self.assertEqual(rc, 2)
        self.assertIn("over-long", err)
        self.assertLess(time.monotonic() - started, 10)

    def test_terminal_escapes_from_the_far_end_are_neutralised(self):
        rc, out, err = self.run_client("51234-exceed-souvenir",
                                       service=ESCAPING_SERVICE)
        self.assertNotIn("\x1b", out + err)
        self.assertIn("wiped", err)
        self.assertIn("disp0", out)

    def test_no_partial_file_survives_any_failure(self):
        for svc in [service(declared=1000, body=b"short"),
                    service(sha="0" * 64), SLOW_EVIL_SERVICE]:
            with self.subTest(svc=svc[-60:]):
                self.run_client("51234-exceed-souvenir", "--size-cap", "100",
                                service=svc)
                self.assertEqual(self.landed(), [])

    def test_landing_never_clobbers_even_when_raced(self):
        """The claim on a name is link(2), which fails if it exists: a
        check-then-rename would let a concurrent receive overwrite."""
        self.dest.mkdir(parents=True)
        (self.dest / "a.txt").write_bytes(b"first")
        tmp = self.dest / ".partial"
        tmp.write_bytes(b"second")
        got = recv.land(tmp, self.dest, "a.txt")
        self.assertEqual(got.name, "a.1.txt")
        self.assertEqual((self.dest / "a.txt").read_bytes(), b"first")
        self.assertFalse(tmp.exists())

    # --- policy -------------------------------------------------------------

    def test_a_refusal_is_diagnosed_as_policy(self):
        rc, _, err = self.run_client("51234-exceed-souvenir",
                                     qrexec=REFUSING_QREXEC)
        self.assertEqual(rc, 126)
        self.assertIn("no policy line", err)
        self.assertEqual(self.landed(), [])


class RecvGateCase(RecvBase):
    def test_bin_and_library_name_the_same_gate_path(self):
        lit = re.search(r'_APPROVAL_CONF = "([^"]+)"', CLIENT.read_text()).group(1)
        self.assertEqual(lit, "/usr/local/etc/approval.d/50-oci.conf")
        self.assertEqual(lit, re.search(
            r'APPROVAL_CONF = "([^"]+)"',
            (ROOT / "share" / "qvmwh.py").read_text()).group(1))

    def test_approve_asks_about_the_held_file_then_lands_it(self):
        self.gate()
        rc, _, err = self.run_client("51234-exceed-souvenir",
                                     WH_RECV_NAME="report.pdf",
                                     WH_RECV_CONTENT="PAYLOAD")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.landed(), ["report.pdf"])
        req = self.request()["request"]
        self.assertEqual((req["action"], req["shape"], req["provider"]),
                         ("wormhole.recv.offer", "inbound-offer",
                          "qvm-wormhole-recv"))
        self.assertEqual(req["subject"], {
            "offer": {"name": "report.pdf", "size": 7,
                      "sha256": hashlib.sha256(b"PAYLOAD").hexdigest()},
            "into": str(self.dest)})
        self.assertEqual(req["targets"], ["@dispvm:wormhole_dvm"])
        self.assertEqual(req["digest"], qvmwh.request_digest(
            req["action"], req["shape"], req["subject"], req["targets"]))
        self.assertEqual(req["wait_s"], 10)
        self.assertEqual(self.request()["env"], {"PATH": "/usr/bin:/bin"})
        self.assertEqual(self.journal()["approval"], "approved")

    def test_deny_lands_nothing_and_the_handler_discards(self):
        self.gate("deny")
        rc, out, err = self.run_client("--json", "51234-exceed-souvenir")
        self.assertEqual(rc, 125, err)
        self.assertEqual(self.landed(), [])
        self.assertFalse((self.home / "qvm-wormhole-out").exists(),
                         "the handler left the held file behind")
        evs = [json.loads(line) for line in out.splitlines()]
        self.assertEqual([e["event"] for e in evs],
                         ["waiting", "offer", "approval", "done"])
        self.assertEqual(evs[2]["decision"], "deny")
        self.assertEqual(self.journal()["approval"], "denied")
        self.assertEqual(self.journal()["exit"], 125)

    def test_a_contract_breaking_reply_is_a_refusal(self):
        self.gate("wrong_digest")
        rc, _, _ = self.run_client("51234-exceed-souvenir")
        self.assertEqual(rc, 125)
        self.assertEqual(self.landed(), [])
        self.assertTrue(self.journal()["approval"].startswith("error:"))

    def test_a_broken_gate_refuses_before_any_call(self):
        marker = self.d / "called"
        self.gate(text="approver = /nonexistent/approver\n")
        rc, _, err = self.run_client("51234-exceed-souvenir",
                                     qrexec=MARK_QREXEC % marker)
        self.assertEqual(rc, 125)
        self.assertIn("broken", err)
        self.assertFalse(marker.exists(), "a disposable was requested")
        self.assertEqual(self.landed(), [])

    def test_hostile_env_is_ignored_while_gated(self):
        self.gate()
        rc, _, err = self.run_client(
            "51234-exceed-souvenir",
            QVM_WORMHOLE_QREXEC=str(self.d / "nonexistent-qrexec"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.landed(), ["got.txt"])

    def test_contract_reports_the_gate(self):
        self.gate()
        rc, out, _ = self.run_client("--contract")
        c = json.loads(out)
        self.assertTrue(c["gated"] and c["approver_ok"])
        self.assertEqual(c["approver"], str(self.d / "approver"))
        self.assertFalse(self.rec.exists(), "--contract ran the approver")

    def test_approver_wait_can_only_shorten(self):
        self.gate()
        self.conf.write_text(self.conf.read_text().replace(
            "approver_timeout = 10", "approver_timeout = 300"))
        rc, _, err = self.run_client("51234-exceed-souvenir",
                                     "--approver-wait", "20")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.request()["request"]["wait_s"], 20)
        self.assertEqual(self.run_client("7-a-b", "--approver-wait", "5")[0], 2)


class LibraryCase(unittest.TestCase):
    def test_safe_name_refuses_what_a_human_could_be_fooled_by(self):
        for raw in ["a‮txt.exe", "a\x7f", "a​b", "x\ny", ""]:
            with self.subTest(raw=raw):
                self.assertEqual(qvmwh.safe_name(raw), "received.bin")
        self.assertEqual(qvmwh.safe_name("Report 2026.pdf"), "Report 2026.pdf")
        self.assertEqual(qvmwh.safe_name("日本.txt"), "日本.txt")


class SharedContractCase(unittest.TestCase):
    def test_both_handlers_use_the_same_code_regex_as_the_library(self):
        """Three copies of this pattern exist. If they drift, transfers fail at
        the far end with 'malformed code' and the cause is three files apart."""
        pats = {qvmwh.CODE_RE.pattern}
        for h in ["wormhole.Send", "wormhole.Recv"]:
            src = (ROOT / "qrexec" / h).read_text()
            pats.add(src.split('CODE_RE = re.compile(r"', 1)[1].split('")', 1)[0])
        self.assertEqual(len(pats), 1, "CODE_RE has drifted: %r" % pats)

    def test_handler_and_library_sanitise_names_alike(self):
        handler = load(HANDLER, "wormhole_recv_handler")
        for raw in ["ok.txt", "../x", "a‮b", "a\x7f", "-rf", "日本.txt"]:
            with self.subTest(raw=raw):
                self.assertEqual(handler.safe_name(raw), qvmwh.safe_name(raw))

    def test_minted_codes_satisfy_that_regex(self):
        words = qvmwh.load_wordlist()
        for _ in range(200):
            self.assertRegex(qvmwh.mint_code(words), qvmwh.CODE_RE)


if __name__ == "__main__":
    unittest.main()
