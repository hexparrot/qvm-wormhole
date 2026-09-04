#!/bin/sh
# Run IN the TemplateVM (e.g. fedora-42), as root:
#     sudo sh install-template.sh
#
# Installs the CLIENTS only. No wormhole binary is installed here -- the calling
# qube never needs one.
#
# Everything lands under /usr, NOT /usr/local. In an AppVM /usr/local is
# bind-mounted from /rw/usrlocal, so a template's /usr/local is masked in every
# child: the install would appear to succeed and the command would not exist.
set -eu
here="$(cd "$(dirname "$0")" && pwd -P)"

persist="$(qubesdb-read /qubes-vm-persistence 2>/dev/null || echo unknown)"
if [ "$persist" != "full" ] && [ "${FORCE:-}" != "1" ]; then
  echo "error: /qubes-vm-persistence is '$persist', expected 'full'." >&2
  echo "This looks like an AppVM or a disposable, where changes to /usr are" >&2
  echo "discarded at shutdown. Run this in the TemplateVM, or set FORCE=1 if" >&2
  echo "you know better." >&2
  exit 1
fi

install -D -m 0755 -o root -g root "${here}/bin/qvm-wormhole"      /usr/bin/qvm-wormhole
install -D -m 0755 -o root -g root "${here}/bin/qvm-wormhole-recv" /usr/bin/qvm-wormhole-recv
install -D -m 0644 -o root -g root "${here}/share/qvmwh.py"        /usr/share/qvm-wormhole/qvmwh.py
install -D -m 0644 -o root -g root "${here}/share/wordlist.txt"    /usr/share/qvm-wormhole/wordlist.txt
if [ -f /etc/qvm-wormhole.conf ]; then
  echo "note: keeping existing /etc/qvm-wormhole.conf"
else
  install -D -m 0644 -o root -g root "${here}/etc/qvm-wormhole.conf" /etc/qvm-wormhole.conf
fi

ls -l /usr/bin/qvm-wormhole /usr/bin/qvm-wormhole-recv \
      /usr/share/qvm-wormhole/qvmwh.py /usr/share/qvm-wormhole/wordlist.txt
echo
echo "Installed. Shut the template down, then in a child qube:  qvm-wormhole --help"
echo "It stays inert until dom0 has a line from qrexec/30-wormhole.policy."
