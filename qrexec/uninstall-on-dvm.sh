#!/bin/sh
# Remove the wormhole.Send / wormhole.Recv handlers. Run IN the DVM template
# (e.g. wormhole_dvm), as root -- the same place install-on-dvm.sh ran:
#     sudo sh uninstall-on-dvm.sh
#
# It does not remove magic-wormhole itself (run `pipx uninstall magic-wormhole`
# as the user if you want that too), and it does not touch dom0. Shut the DVM
# template down afterwards so new disposables stop inheriting the handlers.
# DESTDIR prefixes every path; it exists for the tests.
set -eu
D="${DESTDIR:-}"

if [ -z "$D" ]; then
  if [ "$(id -u)" != 0 ]; then
    echo "error: run as root: sudo sh uninstall-on-dvm.sh" >&2
    exit 1
  fi
  persist="$(qubesdb-read /qubes-vm-persistence 2>/dev/null || echo unknown)"
  case "$persist" in
    none)
      echo "error: this IS a disposable -- a removal here is lost at shutdown." >&2
      echo "Run this in the DVM template itself." >&2
      exit 1 ;;
    rw-only) ;;
    *)
      [ "${FORCE:-}" = 1 ] || {
        echo "error: /qubes-vm-persistence is '$persist'; the handlers live in a DVM" >&2
        echo "template (an AppVM). Set FORCE=1 if you know better." >&2
        exit 1
      } ;;
  esac
fi

for svc in wormhole.Send wormhole.Recv; do
  f="/usr/local/etc/qubes-rpc/$svc"
  if [ -e "$D$f" ] || [ -L "$D$f" ]; then
    rm -f "$D$f"
    echo "removed $f"
  fi
done
echo "Handlers removed. Now, in dom0: qvm-shutdown wormhole_dvm"
