# Installing on a fresh Qubes system

Every command below is labelled with **the qube it runs in**. That label is the
part people get wrong; almost every failure in `failure-modes.md` traces to a
command run in the wrong machine.

Assumed starting point: a stock Qubes install with a `fedora-XX` template,
`sys-firewall`, and at least one AppVM. `dev` below is whatever qube you keep
this repo in.

---

## 1. Create the DispVM template — in **dom0**

```
qvm-create --class AppVM --template fedora-XX --label red wormhole_dvm
qvm-prefs  wormhole_dvm template_for_dispvms True
qvm-prefs  wormhole_dvm netvm sys-firewall
```

`wormhole_dvm` is a name, not a requirement — but it must match both
`/etc/qvm-wormhole.conf` and the policy line in step 5.

**It needs a netvm.** This is the one machine in the design that talks to the
network; without one, every transfer fails in a way that looks like a firewall
problem.

Sending files larger than ~2 GiB also needs a bigger private volume, because the
disposable stores the file before sending it:

```
qvm-volume resize wormhole_dvm:private 20G
```

## 2. Put magic-wormhole in the DispVM template — in **wormhole_dvm**

`qvm-start wormhole_dvm`, open a terminal in it, then:

```
sudo dnf install -y pipx
pipx install magic-wormhole
~/.local/bin/wormhole --version
```

magic-wormhole was dropped from Fedora after F36, so there is no RPM — pipx from
PyPI is the normal route. If this machine cannot reach PyPI, build an offline
wheelhouse elsewhere and `pipx install --pip-args="--no-index --find-links=..."`.

This lands in `~/.local`, which is on the private volume, which every disposable
spawned from this template inherits. That is the whole mechanism.

## 3. Install the service — in **wormhole_dvm**

From `dev`, `qvm-copy` the repo's `qrexec/` directory to `wormhole_dvm`, then:

```
cd ~/QubesIncoming/dev/qrexec
sudo sh install-on-dvm.sh
```

It refuses to run in a disposable or a TemplateVM, and warns if it cannot find a
wormhole binary for the service user.

Then, **in dom0**: `qvm-shutdown wormhole_dvm`. Disposables clone the template's
private volume at spawn time, so nothing you did in steps 2–3 reaches them until
it has been shut down once.

## 4. Install the client — in your **AppVM TemplateVM**

The template your *sending* qubes inherit from — e.g. `fedora-XX`. `qvm-copy` the
repo to it, then:

```
cd ~/QubesIncoming/dev/qvm-wormhole
sudo sh install-template.sh
```

No wormhole binary is installed here; the sending qube never needs one.

Then **in dom0**: `qvm-shutdown <template>`, and restart any AppVM that should
get the command.

## 5. Grant the capability — in **dom0**

Nothing works yet, by design. Create `/etc/qubes/policy.d/30-wormhole.policy`
(type it; do not copy files into dom0):

```
wormhole.Send  +file  personal  @dispvm:wormhole_dvm  allow
wormhole.Send  *      @anyvm    @anyvm                deny
```

One `allow` line per qube that may send. The catch-all `deny` goes last.

**The target must name the template.** A bare `@dispvm` rule *refuses* a caller
that names one, and the resulting rc 126 is indistinguishable from having no
rule at all.

## 6. Verify — in the granted AppVM

```
qvm-wormhole --help
echo hello > /tmp/t.txt
qvm-wormhole /tmp/t.txt
```

It prints a code and the exact `wormhole receive <code>` line. Run that on the
other computer. You should see `Transfer complete.`

## 7. Verify the blast radius — in an **ungranted** AppVM

Just as important as step 6:

```
qvm-wormhole /tmp/t.txt
```

Expect `rc 126` and "dom0 refused". If this *succeeds*, your policy is wider
than you think — check for an `@anyvm` allow line.

---

## If something fails

| Where you are | Check |
|---|---|
| rc 126 everywhere | policy file name sorts before `90-default.policy`; the DVM template name matches exactly in all three places |
| `command not found` | the AppVM was not restarted after the template shut down |
| `no wormhole binary found` | step 2 ran in the wrong VM, or step 3's shutdown was skipped |
| every relay probe fails | the DVM template has no netvm, or a minimal template is missing `qubes-core-agent-networking` |

`docs/failure-modes.md` has the full table. `tools/dvm-run` is a read-only probe
that isolates transport from service:

```
tools/dvm-run --target '@dispvm:wormhole_dvm' --label probe -c 'hostname; wormhole --version'
```
