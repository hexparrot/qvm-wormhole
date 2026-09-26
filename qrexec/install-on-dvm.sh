#!/bin/sh
# Run IN the DVM template (e.g. wormhole_dvm), as root, with wormhole.Send
# staged next to it:
#     sudo sh install-on-dvm.sh
#
# /usr/local is the persistent half of an AppVM and is inherited by every
# disposable spawned from this template, so this needs no TemplateVM change.
set -eu
here="$(cd "$(dirname "$0")" && pwd -P)"

persist="$(qubesdb-read /qubes-vm-persistence 2>/dev/null || echo unknown)"
case "$persist" in
  none)
    echo "error: this IS a disposable -- nothing here survives its shutdown." >&2
    echo "Run this in the DVM template itself, not in a spawned disposable." >&2
    exit 1 ;;
  full)
    # A TemplateVM's /usr/local is NOT inherited by its AppVMs: they mask it
    # with their own /rw/usrlocal. Installing here is a silent no-op.
    [ "${FORCE:-}" = 1 ] || {
      echo "error: /qubes-vm-persistence is 'full' -- this looks like a" >&2
      echo "TemplateVM. Its /usr/local is masked in every child, so the" >&2
      echo "service would never be found. Run this in the DVM template" >&2
      echo "(an AppVM), or set FORCE=1 if you know better." >&2
      exit 1
    } ;;
  rw-only)
    ;;   # an AppVM or DVM template: the intended place
  *)
    [ "${FORCE:-}" = 1 ] || {
      echo "error: cannot read /qubes-vm-persistence (got '$persist'); this" >&2
      echo "does not look like a Qubes VM. Set FORCE=1 if you know better." >&2
      exit 1
    } ;;
esac

for svc in wormhole.Send wormhole.Recv; do
  install -D -m 0755 -o root -g root "${here}/${svc}" "/usr/local/etc/qubes-rpc/${svc}"
done
ls -l /usr/local/etc/qubes-rpc/wormhole.Send /usr/local/etc/qubes-rpc/wormhole.Recv

# Look where the SERVICE will look, as the user it runs as. Under sudo $HOME is
# /root, which is never where the qrexec service finds anything.
user_home="$(getent passwd "${SUDO_USER:-user}" | cut -d: -f6)"
: "${user_home:=/home/user}"
found=0
for p in \
    "${user_home}/.local/bin/wormhole" \
    "${user_home}/.local/share/pipx/venvs/magic-wormhole/bin/wormhole" \
    /opt/wormhole/bin/wormhole \
    /usr/bin/wormhole
do
  if [ -x "$p" ]; then
    echo "wormhole binary: $p"
    found=1
    break
  fi
done
if [ "$found" = 0 ]; then
  echo "WARNING: no wormhole binary found for user '${SUDO_USER:-user}'." >&2
  echo "Provision this DVM template before expecting a transfer to work." >&2
fi

echo
echo "Installed. Shut this VM down so disposables inherit it, then from a granted qube:"
echo "    qvm-wormhole ./somefile"
echo "dom0 needs, per caller and per direction:"
echo "    wormhole.Send  +file  <caller>  @dispvm:$(hostname)  allow"
echo "    wormhole.Recv  +file  <caller>  @dispvm:$(hostname)  allow"
