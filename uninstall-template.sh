#!/bin/sh
# Remove the qvm-wormhole CLIENTS. Run where install-template.sh ran -- the
# TemplateVM your AppVMs inherit from, or a StandaloneVM -- as root:
#     sudo sh uninstall-template.sh [--purge] [--keep-gate]
#
#   --purge      also remove /etc/qvm-wormhole.conf (kept by default, just as
#                install-template.sh never overwrites it)
#   --keep-gate  proceed although an approval gate file is present (below)
#
# It refuses while /usr/local/etc/approval.d/50-oci.conf exists on THIS machine:
# that file belongs to whatever installed the approver, and removing the client
# under it hides a configuration someone relies on. Remove the gate with its own
# tool first, or pass --keep-gate to leave it for a later reinstall (which will
# then be gated again). In a TemplateVM the gate files live in the AppVMs'
# /usr/local, which this script cannot see: check them yourself.
#
# Per-user state is left alone: ~/.local/state/qvm-wormhole (the audit journal)
# and ~/QubesIncoming/wormhole (received files). DESTDIR prefixes every path;
# it exists for the tests.
set -eu
purge=0
keep_gate=0
for a in "$@"; do
  case "$a" in
    --purge) purge=1 ;;
    --keep-gate) keep_gate=1 ;;
    *) echo "usage: sudo sh uninstall-template.sh [--purge] [--keep-gate]" >&2; exit 2 ;;
  esac
done
D="${DESTDIR:-}"

if [ -z "$D" ]; then
  if [ "$(id -u)" != 0 ]; then
    echo "error: run as root: sudo sh uninstall-template.sh" >&2
    exit 1
  fi
  persist="$(qubesdb-read /qubes-vm-persistence 2>/dev/null || echo unknown)"
  if [ "$persist" != "full" ] && [ "${FORCE:-}" != "1" ]; then
    echo "error: /qubes-vm-persistence is '$persist', expected 'full'." >&2
    echo "In an AppVM /usr comes from the template and the removal would be" >&2
    echo "undone at the next boot. Run this where install-template.sh ran, or" >&2
    echo "set FORCE=1 if you know better." >&2
    exit 1
  fi
fi

gate="$D/usr/local/etc/approval.d/50-oci.conf"
if [ -e "$gate" ] || [ -L "$gate" ]; then
  if [ "$keep_gate" != 1 ]; then
    echo "error: an approval gate is installed ($gate)." >&2
    echo "Remove it with the tool that installed it first, or pass --keep-gate" >&2
    echo "to leave it in place for a later reinstall." >&2
    exit 1
  fi
  echo "note: leaving $gate in place (--keep-gate); a reinstall will be gated again"
fi

for f in /usr/bin/qvm-wormhole /usr/bin/qvm-wormhole-recv \
         /usr/share/qvm-wormhole/qvmwh.py /usr/share/qvm-wormhole/wordlist.txt; do
  if [ -e "$D$f" ] || [ -L "$D$f" ]; then
    rm -f "$D$f"
    echo "removed $f"
  fi
done
rm -rf "$D/usr/share/qvm-wormhole/__pycache__"
if [ -d "$D/usr/share/qvm-wormhole" ]; then
  if rmdir "$D/usr/share/qvm-wormhole" 2>/dev/null; then
    echo "removed /usr/share/qvm-wormhole/"
  else
    echo "note: /usr/share/qvm-wormhole/ holds files this script did not install; left in place"
  fi
fi
if [ -e "$D/etc/qvm-wormhole.conf" ]; then
  if [ "$purge" = 1 ]; then
    rm -f "$D/etc/qvm-wormhole.conf"
    echo "removed /etc/qvm-wormhole.conf"
  else
    echo "note: kept /etc/qvm-wormhole.conf (--purge removes it)"
  fi
fi
echo
echo "Clients removed. The disposable's handlers and the dom0 policy are separate:"
echo "see 'Uninstall' in README.md."
