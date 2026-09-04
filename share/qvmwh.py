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
import subprocess
import sys
import threading

CONF = "/etc/qvm-wormhole.conf"
STATE = pathlib.Path(os.path.expanduser("~/.local/state/qvm-wormhole"))
QREXEC = os.environ.get("QVM_WORMHOLE_QREXEC", "/usr/lib/qubes/qrexec-client-vm")
CHUNK = 1024 * 1024
MAX_TIMEOUT = 86400

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

WORDLIST_PATHS = [
    os.environ.get("QVM_WORMHOLE_WORDLIST"),
    "/usr/share/qvm-wormhole/wordlist.txt",
    str(pathlib.Path(__file__).resolve().parent / "wordlist.txt"),
]

PROG = "qvm-wormhole"


def fail(message, prog=None):
    """Exit 2 for anything the caller got wrong.

    The exit codes are a contract shared by both directions: 0 done, 1 the
    transfer failed, 2 bad input, 124 timed out, 126 dom0 refused, 130
    cancelled. A validation error must never look like a failed transfer.
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


def load_wordlist():
    """The PGP even/odd lists, extracted from magic-wormhole itself.

    Shipped as data so a sending qube needs no wormhole install to mint a code.
    """
    for p in WORDLIST_PATHS:
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
         + ", ".join(p for p in WORDLIST_PATHS if p))


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


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


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


def spawn(target, service, verb, prog=None):
    argv = [QREXEC, "--no-filter-escape-chars-stdout",
            "--no-filter-escape-chars-stderr", "--",
            target, "%s+%s" % (service, verb)]
    try:
        return subprocess.Popen(argv, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        fail("cannot run %s: %s" % (QREXEC, e), prog)


def refusal_note(service, target, prog=None):
    return ("%s: dom0 refused %s to %s.\nThis qube has no policy line for that "
            "target; retrying cannot help, and no disposable was created."
            % (prog or PROG, service, target))


def read_exact(stream, n):
    """Read exactly n bytes or return short. Never depends on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(min(CHUNK, n - len(buf)))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def read_line(stream, limit=8192):
    """Bounded readline over a binary stream. An unbounded one is a memory DoS
    from a peer that never sends a newline."""
    buf = bytearray()
    while len(buf) < limit:
        b = stream.read(1)
        if not b:
            return None
        if b == b"\n":
            return bytes(buf)
        buf += b
    return None


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
