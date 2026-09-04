# Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `Request refused`, exit 126 | no dom0 policy line for this qube, **or** the DVM template named in `--dvm`/conf does not exist, **or** it lacks `template_for_dispvms` | all three look identical at the call site. Check the VM name first — it is the cheapest to rule out |
| exit 126 when the caller names the template | the dom0 rule says bare `@dispvm` | write the rule as `@dispvm:<template>`; that form accepts both spellings |
| `qvm-wormhole: command not found` in an AppVM, though it installed fine in the template | installed to `/usr/local/bin` | `/usr/local` is masked in AppVMs by the `/rw/usrlocal` bind-mount. Install to `/usr/bin` |
| `no wormhole binary found in this disposable` | the DVM template is not provisioned, or wormhole was installed in the *underlying TemplateVM's* home rather than the DVM template's | install into the DVM template's `~/.local`; verify in a **spawned disposable**, not the template |
| every relay probe fails from the disposable | on a minimal template, `qubes-core-agent-networking` is missing | install it. This is indistinguishable from a firewalled relay — check it before suspecting your netvm |
| `malformed code` from the service | client and handler disagree on code shape | `tests/test_client.py` guards this; run the tests |
| transfer fails with a wrong-password error | the receiver typed a different case than was minted | codes are lowercased at mint time precisely to prevent this; report it if it recurs |
| `wormhole did not finish within Ns`, exit 124 | nobody ran `wormhole receive`, **or** the transfer was still in flight — `--timeout` covers both | raise `--timeout`; the disposable is destroyed either way |
| `not enough room in this disposable` | the file is larger than the disposable's private volume (2 GiB by Qubes default) | enlarge the DVM template's private volume, and raise `WORMHOLE_SEND_SIZE_CAP` |
| `changed while sending (N of M bytes)`, exit 1 | the source was truncated or rewritten after it was measured | send a stable copy; nothing was offered to a receiver |
| `could not read <path>`, exit 1 | the source became unreadable mid-stream (EIO, an unmounted share) | nothing was offered to a receiver; the disposable is gone |
| mailbox reported "crowded" | nameplate collision on the public relay — someone else holds the same one | rare with a 5-digit nameplate. Re-run; a fresh code is minted each time |
| transfer hangs with no output | DispVM cold start | first call is slowest; budget for it in `--timeout` |

## Receiving

| Symptom | Cause | Fix |
|---|---|---|
| `that does not look like a wormhole code` | typo, or the sender used `--code-length 1` | codes are `<digits>-<word>-<word>`; retype it |
| `the sender sent a text message, not a file` | the far end ran `wormhole send --text` | this tool moves files; ask for a file |
| `the sender sent a directory` | the far end sent a folder, which wormhole transfers as a directory offer | ask for a single file, or a tarball |
| `sha256 mismatch; the file was discarded` | corruption in transit, or a service that lied | nothing was written; retry |
| `truncated payload: N of M bytes` | the disposable died mid-handback | nothing was written; retry |
| `no way to ask for one (no DISPLAY, no tty)` | run non-interactively with no code | pass the code as an argument |
| received file has an unexpected name | the sender's filename was unusable, so it became `received.bin` | expected; the name is never trusted |

## Cancelling

Ctrl-C. Killing the client drops the vchan, and dom0 destroys the disposable.
Teardown is guaranteed rather than best-effort — this is the intended cancel
path, not an error.

## Diagnosing a refusal you cannot explain

Policy is dom0 state and cannot be read from a qube; the only test is to try.
`tools/dvm-run` is a read-only probe that isolates the transport from the
service:

```
tools/dvm-run --target '@dispvm:wormhole_dvm' --label "probe" -c 'hostname'
```

If that works and `qvm-wormhole` still fails, the problem is the `wormhole.Send`
policy line or the handler — not the DVM template.
