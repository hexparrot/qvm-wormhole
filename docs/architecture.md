# Architecture

## Why a disposable

The calling qube has no network reach and no wormhole binary. It hands the file
to a fresh disposable over qrexec; the disposable has egress, runs
magic-wormhole, and is destroyed when the call returns. The capability is a dom0
policy line, not an installed file.

This also means the *sending* qube's IP is never seen by the relay — the relay
sees the disposable's netvm exit.

## Why one qrexec call, held open

A disposable exists for exactly one qrexec call: **the call returning is the VM
being destroyed.** Detach-and-poll is therefore structurally impossible — a
second call lands in a different machine with nothing carried over.

`wormhole send` prints its code within about a second and then blocks until the
receiver connects. That collides with the above: you need the code early while
the process runs late.

**Resolution: the client mints the code and passes `--code`.** It can print the
code before the transfer even starts, and nothing has to be scraped out of a
blocking process. This was measured, not assumed — `wormhole` writes
`Wormhole code is: …` to **stderr**, along with an ASCII QR block, so parsing it
would have been both fragile and racy.

## Why the service reads stdin

`qubes-rpc-service`'s invariant 4 is `exec </dev/null` — nothing in a handler may
read the caller's stdin. A Send service inverts that, deliberately.

The invariant that *matters* is preserved by other means: **no caller-supplied
string ever reaches a shell as code.**

- The qrexec argument stays a fixed verb table: `file`, nothing else.
- Everything variable rides in a JSON header, where it is parsed and validated.
- The handler is Python and invokes wormhole with an argv **list**. There is no
  shell in the path at all — a stronger guarantee than quoting inside `sh`.
- `filename` is reduced to a basename, so a caller may influence the name but
  never the directory.
- Exactly `size` bytes are read, so the service never depends on EOF or a
  half-closed vchan.

## The audit hole, and where the audit went

The usual pattern puts `logger -t <service>` on the target so `journalctl` says
who asked for what. **A disposable's journal dies with the disposable.**

So the audit lives on the caller: `~/.local/state/qvm-wormhole/journal.jsonl`
records timestamp, resolved absolute path, size, sha256, the disposable's
hostname, outcome and exit code. The handler still calls `syslog` for anyone
watching in real time, but that is a convenience, not the record.

Only the **nameplate** is journalled, never the full code. A single-use secret
written to a logfile outlives its use.

## Trust boundaries

| Component | Sees | Can it read the file? |
|---|---|---|
| Calling qube | plaintext (it owns the file) | yes |
| dom0 policy | the fact of a call | no |
| Disposable | plaintext, briefly | yes — accepted trade-off |
| netvm / network observer | ciphertext, both IPs, size, timing | no |
| Relay operator | ciphertext, IPs, size, timing | **no** — SPAKE2 |
| Receiver with the code | plaintext | yes, by design |

The disposable is the one place the design gives up "plaintext never leaves the
qube". It is ephemeral, holds only the requested file, and is destroyed on exit.
Encrypt before sending if that is not good enough for a given file.
