# qvm-wormhole

Send a file out of any Qubes AppVM, over [magic-wormhole](https://github.com/magic-wormhole/magic-wormhole),
without giving that qube network access or a wormhole binary.

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

## How it works

```
AppVM                          dom0 policy                DispVM (wormhole_dvm)
qvm-wormhole ./report.pdf ──► wormhole.Send +file ──►  wormhole.Send handler
  mints the code                <vm> @dispvm:…             validates the header
  prints it immediately         allow                      writes the payload
  streams header + bytes                                   runs `wormhole send`
```

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
add one line per qube allowed to send:

```
wormhole.Send  +file  <caller>  @dispvm:wormhole_dvm  allow
wormhole.Send  *      @anyvm    @anyvm                deny
```

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

## Notes

- **Ctrl-C is the cancel path.** Killing the client drops the vchan and dom0
  destroys the disposable. Teardown is guaranteed, not best-effort.
- **The audit lives on the caller**, in `~/.local/state/qvm-wormhole/journal.jsonl`
  — a disposable's own journal dies with it. Only the nameplate is recorded,
  never the full code.
- **The disposable sees your file in plaintext.** It is ephemeral and holds only
  that one file, but if that matters, encrypt before sending.
