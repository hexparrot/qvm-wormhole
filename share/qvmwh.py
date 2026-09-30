"""Shared half of qvm-wormhole and qvm-wormhole-recv.

Installed to /usr/share/qvm-wormhole/qvmwh.py. Both front-ends put that
directory on sys.path and `import qvmwh`, so config parsing, code minting, the
audit journal and the qrexec plumbing exist once. Two /usr/bin scripts that
each grew their own copy would drift, and the drift would be silent.
"""

import hashlib
import json
import os
import pathlib
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import threading

CONF = "/etc/qvm-wormhole.conf"
STATE = pathlib.Path(os.path.expanduser("~/.local/state/qvm-wormhole"))
QREXEC_DEFAULT = "/usr/lib/qubes/qrexec-client-vm"
# In-process override for tests only. The QVM_WORMHOLE_QREXEC environment
# variable is read lazily by qrexec_path(), and never while the gate is on.
QREXEC = None
CHUNK = 1024 * 1024
MAX_TIMEOUT = 86400
# Seconds past --timeout before a client shoots the vchan itself. The service
# enforces --timeout on the far side; this is the backstop for a peer that
# never answers at all, and it covers EVERY phase of the call.
GRACE = 60

# @dispvm, @dispvm:<template>, or a plain VM name -- fully anchored. An
# unanchored alternation here would accept anything merely STARTING with
# "dispvm", which dom0 then refuses with a misleading diagnosis.
DVM_RE = re.compile(
    r"^(@dispvm(:[A-Za-z0-9][A-Za-z0-9_.-]*)?|[A-Za-z0-9][A-Za-z0-9_.-]*)$")

# Must match CODE_RE in both handlers. A stock wormhole code has a one-digit
# nameplate ("7-crossover-clockwork"), so the nameplate is 1..6 digits even
# though we always mint five.
CODE_RE = re.compile(r"^[0-9]{1,6}(-[a-z]+){2,}$")

DEFAULTS = {
    "dvm": "wormhole_dvm",
    "size_cap": str(2 * 1024**3),
    "timeout": "3600",
}

WORDLIST_DEFAULTS = [
    "/usr/share/qvm-wormhole/wordlist.txt",
    str(pathlib.Path(__file__).resolve().parent / "wordlist.txt"),
]

# --- optional approval gate (approval-hook v1) ------------------------------
# The PRESENCE of this one file turns the gate on. It is a constant on
# purpose: no argument, config key or environment variable can move it. The
# bin/ scripts carry the same literal to choose their library path before this
# module is imported; a test keeps the two equal.
APPROVAL_CONF = "/usr/local/etc/approval.d/50-oci.conf"
# Who must own the gate's directory, file and approver. Tests patch this
# in-process (they cannot create root-owned files); nothing else can change it.
ROOT_UID = 0
APPROVAL_HOOK = 1          # the approval-hook contract version spoken here
CLI_CONTRACT = 1           # the CLI/--json/exit-code contract version
EXIT_NOT_APPROVED = 125
DEFAULT_APPROVER_TIMEOUT = 420
APPROVER_TIMEOUT_RANGE = (10, 3600)
APPROVER_ENV = {"PATH": "/usr/bin:/bin"}
APPROVER_EXTRA_WAIT = 15   # seconds past wait_s before the approver is stopped
APPROVER_KILL_GRACE = 5    # SIGTERM -> SIGKILL
MSG_LIMIT = 8192           # request and reply lines
STDERR_CAP = 4096
REQUESTER_DEFAULT = "qvm-wormhole command line"
REQUESTER_MAX = 120

PROG = "qvm-wormhole"


def fail(message, prog=None):
    """Exit 2 for anything the caller got wrong.

    The exit codes are a contract shared by both directions: 0 done, 1 the
    transfer failed, 2 bad input, 124 timed out, 125 not approved (or the
    approval gate is on but broken), 126 dom0 refused, 130 cancelled. A
    validation error must never look like a failed transfer.
    """
    print("%s: %s" % (prog or PROG, message), file=sys.stderr)
    sys.exit(2)


def load_conf():
    """Config precedence: built-in defaults < /etc conf < QVM_WORMHOLE_* env."""
    conf = dict(DEFAULTS)
    try:
        for line in pathlib.Path(CONF).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip().lower()
            if k in conf:
                conf[k] = v.strip()
    except FileNotFoundError:
        pass
    for k in conf:
        env = os.environ.get("QVM_WORMHOLE_" + k.upper())
        if env:
            conf[k] = env
    return conf


def conf_int(conf, key):
    """A malformed /etc value must not crash --help with a traceback."""
    try:
        return int(conf[key])
    except (TypeError, ValueError):
        fail("%s: %r is not an integer (check %s or QVM_WORMHOLE_%s)"
             % (key, conf[key], CONF, key.upper()))


def wordlist_paths(gated=False):
    """While the gate is on, QVM_WORMHOLE_WORDLIST is ignored: a planted list
    would make the code guessable by a stranger at the relay."""
    env = None if gated else os.environ.get("QVM_WORMHOLE_WORDLIST")
    return [env] + WORDLIST_DEFAULTS


def qrexec_path(gated=False):
    """The qrexec client to run. QVM_WORMHOLE_QREXEC is honoured only while
    the gate is off."""
    if QREXEC:
        return QREXEC
    if not gated:
        env = os.environ.get("QVM_WORMHOLE_QREXEC")
        if env:
            return env
    return QREXEC_DEFAULT


def load_wordlist(gated=False):
    """The PGP even/odd lists, extracted from magic-wormhole itself.

    Shipped as data so a sending qube needs no wormhole install to mint a code.
    """
    paths = wordlist_paths(gated)
    for p in paths:
        if not p:
            continue
        try:
            text = pathlib.Path(p).read_text()
        except OSError:
            continue
        section, words = None, {"even": [], "odd": []}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line == "[even]":
                section = "even"
            elif line == "[odd]":
                section = "odd"
            elif section:
                words[section].append(line)
        if len(words["even"]) >= 16 and len(words["odd"]) >= 16:
            return words
    fail("no usable wordlist found; looked in "
         + ", ".join(p for p in paths if p))


def mint_code(words):
    """A 5-digit nameplate widens the space against collisions on the public
    relay. Entropy comes from secrets -- never from a caller, a clock, or a
    language model.

    Words are lowercased. The PGP list ships mixed case ("Aztec", "Chicago"),
    and the code IS the PAKE password: if we mint "Aztec" and the human at the
    other end types "aztec", the two sides derive different keys and the
    transfer fails with a wrong-password error that looks like an attack. One
    canonical case removes the whole class.
    """
    nameplate = secrets.randbelow(90000) + 10000
    return "%d-%s-%s" % (nameplate,
                         secrets.choice(words["even"]).lower(),
                         secrets.choice(words["odd"]).lower())


def measure(path):
    """(size, sha256) from a single read. Taking the size from a separate
    stat() lets a file that grows between the two calls ship a digest over
    more bytes than the declared size, which the far end then reports as a
    digest mismatch rather than the truth: the file changed."""
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
            n += len(chunk)
    return n, h.hexdigest()


def safe_name(raw, fallback="received.bin"):
    """A remote party may influence a file's NAME but never its PATH.

    Applied on both sides deliberately: the service reduces what wormhole
    wrote, and the client reduces what the service declared. The name
    originates with the remote sender, so neither end trusts it.
    """
    name = os.path.basename(str(raw))
    if not name or name in (".", "..") or name.startswith("-"):
        return fallback
    if "/" in name or "\0" in name or any(ord(c) < 32 for c in name):
        return fallback
    return name[:200]


def target_for(dvm):
    return dvm if dvm.startswith("@") else "@dispvm:" + dvm


def spawn(target, service, verb, prog=None, raw_stdout=False, gated=False):
    """qrexec-client-vm filters terminal escapes out of both streams by
    default. Only a caller expecting BINARY on stdout may switch that off,
    and only for stdout: stderr is always shown to a human."""
    qrexec = qrexec_path(gated)
    argv = [qrexec]
    if raw_stdout:
        argv.append("--no-filter-escape-chars-stdout")
    argv += ["--", target, "%s+%s" % (service, verb)]
    try:
        return subprocess.Popen(argv, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        fail("cannot run %s: %s" % (qrexec, e), prog)


def refusal_note(service, target, prog=None):
    return ("%s: dom0 refused %s to %s.\nThis qube has no policy line for that "
            "target; retrying cannot help, and no disposable was created."
            % (prog or PROG, service, target))


def printable(text, keep_newlines=False):
    """Reduce text that came back up the call to something safe to print.

    The disposable's stdout/stderr are relayed with qrexec's escape filter
    off for the payload stream, and JSON decoding restores any control
    characters a service or the remote sender managed to place in a message.
    Nothing from the far end may drive the caller's terminal.
    """
    if isinstance(text, bytes):
        text = text.decode(errors="replace")
    out = []
    for c in str(text):
        if c == "\n" and keep_newlines:
            out.append(c)
        elif c == "\t" or (c.isprintable() and c != "\x7f"):
            out.append(c)
        else:
            out.append("?")
    return "".join(out)


def drain_stderr(proc):
    """Read stderr to EOF on a thread. Both clients block on the other pipe
    for the length of a transfer; an undrained stderr larger than the pipe
    buffer would wedge the peer, and therefore the client, with no timeout
    covering it."""
    buf = []
    t = threading.Thread(target=lambda: buf.append(proc.stderr.read() or b""),
                         daemon=True)
    t.start()
    return t, buf


class LineTooLong(Exception):
    """A status line exceeded the bound. Distinct from EOF: the caller must
    treat it as a protocol violation rather than a clean close."""


def read_line(stream, limit=8192):
    """Bounded readline over a binary stream. An unbounded one is a memory DoS
    from a peer that never sends a newline. Returns None on EOF; raises
    LineTooLong past the bound, so the two cannot be confused."""
    buf = bytearray()
    while len(buf) < limit:
        b = stream.read(1)
        if not b:
            return None
        if b == b"\n":
            return bytes(buf)
        buf += b
    raise LineTooLong(limit)


def journal(record, prog=None):
    """Audit lives on the CALLER, because a disposable's journal dies with the
    disposable. Never record a full transfer code: it is a single-use secret
    that would outlive its use in a logfile.
    """
    try:
        STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (STATE / "journal.jsonl").open("a") as fh:
            fh.write(json.dumps(record) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as e:
        print("%s: warning: could not journal: %s" % (prog or PROG, e),
              file=sys.stderr)


def drain_status(proc, status, on_message=None):
    """Read the service's newline-delimited JSON status objects on a thread.

    Draining concurrently with writing removes a class of pipe-buffer
    deadlocks rather than trusting the service's promise not to speak early.
    """
    def run():
        for raw in proc.stdout:
            try:
                msg = json.loads(raw.decode(errors="replace"))
            except ValueError:
                continue
            status.update(msg)
            if on_message:
                on_message(msg)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


# --- approval gate -----------------------------------------------------------

class GateError(Exception):
    """The gate file is present but something about it (or its approver) is
    wrong. Always a refusal, never a fallback to ungated."""


def _check_owned(st, what, want):
    if not want(st.st_mode):
        raise GateError("%s is not a %s" % (what, "directory" if want is stat.S_ISDIR
                                            else "regular file"))
    if st.st_uid != ROOT_UID:
        raise GateError("%s is not owned by uid %d" % (what, ROOT_UID))
    if st.st_mode & 0o022:
        raise GateError("%s is group- or world-writable" % what)


def _parse_gate(text):
    keys = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            raise GateError("line %d is not key = value" % n)
        k, v = line.split("=", 1)
        k, v = k.strip().lower(), v.strip()
        if k in keys:
            raise GateError("duplicate key %r" % k)
        keys[k] = v
    return keys


def gate_state():
    """(gated, info, error). Not gated when the file does not exist at all
    (lexists: a dangling symlink counts as present, and broken). When gated,
    `info` carries whatever could be read ({"approver", "approver_timeout"})
    and `error` is None only if everything checks out."""
    path = APPROVAL_CONF
    if not os.path.lexists(path):
        return False, {}, None
    info = {}
    try:
        _check_owned(os.lstat(os.path.dirname(path)), os.path.dirname(path),
                     stat.S_ISDIR)
        _check_owned(os.lstat(path), path, stat.S_ISREG)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _check_owned(os.fstat(fd), path, stat.S_ISREG)
            with os.fdopen(os.dup(fd), "rb") as fh:
                data = fh.read(65536)
        finally:
            os.close(fd)
        try:
            keys = _parse_gate(data.decode("utf-8"))
        except UnicodeDecodeError:
            raise GateError("not UTF-8")
        approver = keys.get("approver")
        if not approver:
            raise GateError("no approver = line")
        info["approver"] = approver
        raw_t = keys.get("approver_timeout", str(DEFAULT_APPROVER_TIMEOUT))
        if not re.fullmatch(r"[0-9]{1,5}", raw_t):
            raise GateError("approver_timeout %r is not an integer" % raw_t)
        t = int(raw_t)
        lo, hi = APPROVER_TIMEOUT_RANGE
        if not lo <= t <= hi:
            raise GateError("approver_timeout %d is outside %d..%d" % (t, lo, hi))
        info["approver_timeout"] = t
        if not os.path.isabs(approver):
            raise GateError("approver is not an absolute path")
        _check_owned(os.lstat(approver), approver, stat.S_ISREG)
        if not os.access(approver, os.X_OK):
            raise GateError("approver is not executable")
    except GateError as e:
        return True, info, "%s: %s" % (path, e)
    except OSError as e:
        where = e.filename if e.filename and e.filename != path else "the file"
        return True, info, "%s: %s: %s" % (path, where, e.strerror or e)
    return True, info, None


def canon(obj):
    """The one canonical byte form the digest is taken over."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def request_digest(action, shape, subject, targets):
    return "sha256:" + hashlib.sha256(canon({
        "action": action, "shape": shape, "subject": subject,
        "targets": targets})).hexdigest()


def send_request(path, name, size, sha256, target, wait_s, requester):
    subject = {"file": {"name": name, "path": path, "size": size,
                        "sha256": sha256}}
    targets = [target]
    return {
        "v": APPROVAL_HOOK, "type": "request", "id": secrets.token_hex(16),
        "action": "wormhole.send", "shape": "content-out",
        "subject": subject, "targets": targets,
        "digest": request_digest("wormhole.send", "content-out", subject,
                                 targets),
        "wait_s": wait_s, "requester": requester, "provider": "qvm-wormhole",
    }


def _stop(proc):
    """SIGTERM, a short grace, then SIGKILL. The approver withdraws its
    prompt on SIGTERM; SIGKILL is only for one that will not."""
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
    except OSError:
        return
    try:
        proc.wait(timeout=APPROVER_KILL_GRACE)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait()


def run_approver(approver, request, wait_s):
    """Ask the approver. Returns (decision, reason, stderr_tail) where
    decision is "approve" only if every rule of the contract holds; anything
    else is "deny" (the approver said no) or "error" (it broke the contract).
    KeyboardInterrupt is re-raised after the approver has been stopped."""
    line = json.dumps(request, ensure_ascii=True).encode("ascii") + b"\n"
    if len(line) > MSG_LIMIT:
        return "error", "request too large", b""
    try:
        proc = subprocess.Popen([approver], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=dict(APPROVER_ENV), cwd="/", close_fds=True)
    except OSError as e:
        return "error", "cannot run the approver: %s" % (e.strerror or e), b""
    out, err = bytearray(), bytearray()

    def read_out():
        while True:
            b = proc.stdout.read(4096)
            if not b:
                return
            if len(out) <= MSG_LIMIT:
                out.extend(b)

    def read_err():
        while True:
            b = proc.stderr.read(4096)
            if not b:
                return
            if len(err) < STDERR_CAP:
                err.extend(b[:STDERR_CAP - len(err)])

    to = threading.Thread(target=read_out, daemon=True)
    te = threading.Thread(target=read_err, daemon=True)
    to.start()
    te.start()
    try:
        try:
            proc.stdin.write(line)
        except BrokenPipeError:
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass
        try:
            rc = proc.wait(timeout=wait_s + APPROVER_EXTRA_WAIT)
        except subprocess.TimeoutExpired:
            _stop(proc)
            return "error", "the approver did not answer in time", bytes(err)
    except BaseException:
        _stop(proc)
        raise
    to.join(timeout=5)
    te.join(timeout=5)
    tail = bytes(err)
    if rc != 0:
        return "error", "the approver exited %d" % rc, tail
    data = bytes(out)
    if len(data) > MSG_LIMIT:
        return "error", "reply too large", tail
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        return "error", "reply is not exactly one line", tail
    try:
        reply = json.loads(data.decode("utf-8"))
    except ValueError:
        return "error", "reply is not JSON", tail
    if not isinstance(reply, dict) or reply.get("v") != APPROVAL_HOOK:
        return "error", "reply has the wrong contract version", tail
    if reply.get("id") != request["id"] or reply.get("digest") != request["digest"]:
        return "error", "reply does not match the request", tail
    reason = reply.get("reason", "")
    if not isinstance(reason, str):
        return "error", "reply reason is not text", tail
    reason = printable(reason)[:200]
    if reply.get("decision") == "approve":
        return "approve", reason, tail
    if reply.get("decision") == "deny":
        return "deny", reason or "denied", tail
    return "error", "reply has no valid decision", tail


def stage(src_fd, size_cap, prog=None):
    """Copy the source, from the descriptor already open, into a private
    staging directory, hashing in the same pass. Returns (fd, dir, size,
    sha256): the copy is 0400 and is read back ONLY through `fd` (re-hash,
    stream); nothing is reopened by path. Raises ValueError if the source is
    over the cap while copying (it may grow after a stat)."""
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    d = tempfile.mkdtemp(prefix="stage-", dir=str(STATE))
    fd = None
    try:
        fd = os.open(os.path.join(d, "payload"),
                     os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600)
        try:
            os.lseek(src_fd, 0, os.SEEK_SET)
        except OSError:
            pass
        h, n = hashlib.sha256(), 0
        while True:
            chunk = os.read(src_fd, CHUNK)
            if not chunk:
                break
            n += len(chunk)
            if n > size_cap:
                raise ValueError("over the %d cap" % size_cap)
            h.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(fd, view):]
        os.fchmod(fd, 0o400)
        return fd, d, n, h.hexdigest()
    except BaseException:
        if fd is not None:
            os.close(fd)
        unstage(d)
        raise


def rehash(fd):
    """(size, sha256) of the staged copy, through its descriptor."""
    h, n, off = hashlib.sha256(), 0, 0
    while True:
        chunk = os.pread(fd, CHUNK, off)
        if not chunk:
            return n, h.hexdigest()
        h.update(chunk)
        n += len(chunk)
        off += len(chunk)


def unstage(d):
    if not d:
        return
    try:
        for name in os.listdir(d):
            p = os.path.join(d, name)
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
            os.unlink(p)
        os.rmdir(d)
    except OSError:
        pass
