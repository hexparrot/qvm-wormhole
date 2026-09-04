# qvm-wormhole

Move files in and out of any Qubes AppVM, over
[magic-wormhole](https://github.com/magic-wormhole/magic-wormhole), without
giving that qube network access or a wormhole binary.

```
$ qvm-wormhole ~/Documents/report.pdf
Wormhole code: 51234-exceed-souvenir

On the receiving computer, run:
    wormhole receive 51234-exceed-souvenir

Sending report.pdf (284119 bytes) via a wormhole_dvm disposable.
Waiting for the receiver -- Ctrl-C to cancel.
Disposable disp8101 has the file.
Transfer complete.
```

And the reverse:

```
$ qvm-wormhole-recv
Wormhole code from the sender:  7-crossover-clockwork      # or a zenity prompt
Waiting for the sender via a @dispvm:wormhole_dvm disposable -- Ctrl-C to cancel.
Disposable disp4311 is waiting for the sender.
Received /home/user/QubesIncoming/wormhole/report.pdf (284119 bytes)
```

## How it works

```
AppVM                          dom0 policy                DispVM (wormhole_dvm)
qvm-wormhole ./report.pdf ──► wormhole.Send +file ──►  wormhole.Send handler
  mints the code                <vm> @dispvm:…             validates the header
  prints it immediately         allow                      writes the payload
  streams header + bytes                                   runs `wormhole send`
```

Receiving is the same picture with the arrows reversed: the disposable runs
`wormhole receive` and hands the bytes back up **the same qrexec call**, because
a qrexec call is bidirectional.

**There is no `qubes.Filecopy` anywhere in this design, in either direction.**
That is not a convenience — it is the security property. The disposable never
initiates a connection to anything; it only ever answers a call you made. So
there is no list of recipient qubes to enumerate in dom0, and no rule that would
let a disposable push data into a qube that did not ask for it. A Filecopy-based
return would have been forced to name `@dispvm:<template>` or `@anyvm` as its
*source*, since disposable names are allocated at spawn — exactly the
backpropagation you would not want.

The calling qube never touches the network. The disposable does the transfer and
is destroyed when it finishes. The file is encrypted before it leaves the
disposable — the relay operator cannot read it, and never could: magic-wormhole
uses SPAKE2, so the server never learns the code or the derived key.

**Installing the client grants nothing.** The capability lives in the dom0 policy
line. A qube without one gets `Request refused` (rc 126) and no disposable is
ever created. Install broadly, grant narrowly.

## Requirements

One sentence: **a DispVM template whose disposables have a working `wormhole`
binary and network egress.** The underlying TemplateVM is your choice — minimal,
standard, or one you already have. Nothing here inspects or depends on it.

## Install

Three machines, three steps, in this order. For a from-scratch walkthrough
with every command labelled by qube, see [docs/install.md](docs/install.md).

### 1. The DispVM template (`wormhole_dvm`)

Create it against whatever base you like:

```
# dom0
qvm-create --template <your-template> --label red wormhole_dvm
qvm-prefs  wormhole_dvm template_for_dispvms True
qvm-prefs  wormhole_dvm netvm <your netvm>
```

Install magic-wormhole **inside `wormhole_dvm`**, into `~/.local` — its home is
on the private volume, which every spawned disposable inherits:

```
sha256sum -c SHA256SUMS && ./install.sh      # an offline pipx wheelhouse works
```

Then install the service handler, as root, in the same VM:

```
sudo sh install-on-dvm.sh
```

Shut `wormhole_dvm` down so disposables pick both up.

> **Verify in a *spawned disposable*, never in `wormhole_dvm` itself.** That
> distinction is the entire test — the template having wormhole proves nothing
> about what its disposables inherit.

<details>
<summary>If you chose a minimal template</summary>

| Package | Why | Symptom if missing |
|---|---|---|
| `qubes-core-agent-networking` | minimal templates ship **without networking** | no route in the disposable — and it looks *exactly* like the relay being firewalled |
| `pipx` | the wheelhouse installer uses it | `install.sh` exits "pipx not found" |
| `python3` | wheels are version-tagged | verify the minor version matches your wheel tags |

The first row is the one that wastes an afternoon: a networkless disposable and a
blocked relay produce the same symptom, and only one of them is your fault.
</details>

### 2. The TemplateVM your AppVMs inherit from (e.g. `fedora-XX`)

```
sudo sh install-template.sh
```

Installs `/usr/bin/qvm-wormhole`, `/usr/share/qvm-wormhole/wordlist.txt` and
`/etc/qvm-wormhole.conf`. **No wormhole binary is installed here** — the calling
qube never needs one.

> **Why `/usr/bin` and not `/usr/local/bin`.** In an AppVM `/usr/local` is
> bind-mounted from `/rw/usrlocal`, so a template's `/usr/local` is *masked* in
> every child. Installing there appears to succeed and the command does not
> exist in any AppVM. `install-template.sh` refuses to run anywhere
> `/qubes-vm-persistence` isn't `full`, to catch this before it confuses you.

### 3. dom0

Copy `qrexec/30-wormhole.policy` to `/etc/qubes/policy.d/30-wormhole.policy` and
add one line per qube, **per direction**:

```
wormhole.Send  +file  <caller>  @dispvm:wormhole_dvm  allow
wormhole.Recv  +file  <caller>  @dispvm:wormhole_dvm  allow
wormhole.Send  *      @anyvm    @anyvm                deny
wormhole.Recv  *      @anyvm    @anyvm                deny
```

**The two directions are separate services on purpose.** `wormhole.Send` is an
exfiltration primitive; `wormhole.Recv` is an injection primitive. A hardened
qube can reasonably be allowed to pull files in while remaining unable to send
any out — grant each direction deliberately rather than as a pair.

> The TARGET **must** name the DVM template. A bare `@dispvm` rule *refuses* a
> caller that names one — verified against live dom0, not just the parser.

## Configuration

`/etc/qvm-wormhole.conf` sets `dvm`, `size_cap` and `timeout`. Each is
overridable per-VM by `QVM_WORMHOLE_DVM`, `QVM_WORMHOLE_SIZE_CAP`,
`QVM_WORMHOLE_TIMEOUT` — the supported way for one qube to differ without
editing the template. `wormhole_dvm` is only a default; the name must simply
match your policy line.

**Two caps, and the service's wins.** The client's `size_cap` can only be more
restrictive than the handler's `WORMHOLE_SEND_SIZE_CAP` (default 2 GiB); raising
the client's alone just moves the failure to the far end. Both default to 2 GiB
because **the disposable must store the whole file before sending it**, and a
Qubes private volume is 2 GiB by default. To send more, enlarge the DVM
template's private volume *and* raise the service cap. The handler checks free
space up front and refuses rather than filling the disk mid-transfer.

`timeout` bounds the **whole** transfer — the wait for a receiver *and* the time
the bytes take to move. An 8 GiB file over a slow link needs far more than the
3600s default, or it is killed mid-flight.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | sent and confirmed |
| 1 | the transfer failed |
| 2 | bad input — missing file, empty, over a cap, malformed `--dvm` or `--timeout`. Also surfaces a header rejected by the service |
| 124 | the transfer did not finish in time — nobody collected it, *or* the bytes were still moving |
| 126 | dom0 refused — this qube has no policy line |
| 130 | cancelled with Ctrl-C |

## Tests

```
python3 -m unittest discover -s tests -v
```

No VM, no network. Covers the verb table, the injection corpus, header
validation, path containment, and two drift guards: that the policy file admits
exactly the handler's verbs, and that codes the client mints satisfy the
validator the service enforces.

## Receiving is untrusted input

Sending risks data leaving. Receiving risks data arriving. The received file
comes from whoever holds the code, so:

- it lands in `~/QubesIncoming/wormhole/`, mode `0600`, in a `0700` directory;
- it is **never** given an execute bit and is **never** opened for you;
- an existing file is never clobbered — a second `a.txt` becomes `a.1.txt`;
- the filename is reduced to a basename on **both** sides, because it
  originated with the remote sender and neither end trusts it;
- the payload is written under a temporary name and renamed into place only
  after its digest verifies, so a truncated or corrupt transfer never appears
  as the real file.

Directories and text messages are refused with a clear error; this tool moves
single files.

## Notes

- **Ctrl-C is the cancel path.** Killing the client drops the vchan and dom0
  destroys the disposable. Teardown is guaranteed, not best-effort.
- **The audit lives on the caller**, in `~/.local/state/qvm-wormhole/journal.jsonl`
  — a disposable's own journal dies with it. Only the nameplate is recorded,
  never the full code.
- **The disposable sees your file in plaintext.** It is ephemeral and holds only
  that one file, but if that matters, encrypt before sending.
