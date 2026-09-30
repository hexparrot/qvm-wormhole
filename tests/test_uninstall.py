"""uninstall-template.sh and qrexec/uninstall-on-dvm.sh, run against a fake tree under DESTDIR (never the
real /usr): the clients are removed, the config is kept unless --purge, an approval gate file blocks the
removal unless --keep-gate, and foreign files in /usr/share/qvm-wormhole are left alone."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENTS = ["usr/bin/qvm-wormhole", "usr/bin/qvm-wormhole-recv",
           "usr/share/qvm-wormhole/qvmwh.py", "usr/share/qvm-wormhole/wordlist.txt"]
GATE = "usr/local/etc/approval.d/50-oci.conf"


class Uninstall(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="qvmwh-uninst-")
        self.addCleanup(shutil.rmtree, self.d)

    def make(self, *rels):
        for rel in rels:
            p = os.path.join(self.d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write("x")

    def exists(self, rel):
        return os.path.lexists(os.path.join(self.d, rel))

    def run_script(self, script, *args):
        return subprocess.run(["sh", os.path.join(ROOT, script), *args], capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "DESTDIR": self.d})

    def test_clients_removed_conf_kept(self):
        self.make(*CLIENTS, "etc/qvm-wormhole.conf")
        r = self.run_script("uninstall-template.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(any(self.exists(c) for c in CLIENTS))
        self.assertFalse(self.exists("usr/share/qvm-wormhole"))
        self.assertTrue(self.exists("etc/qvm-wormhole.conf"))
        self.assertIn("kept /etc/qvm-wormhole.conf", r.stdout)

    def test_purge_removes_the_conf(self):
        self.make(*CLIENTS, "etc/qvm-wormhole.conf")
        r = self.run_script("uninstall-template.sh", "--purge")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.exists("etc/qvm-wormhole.conf"))

    def test_a_gate_blocks_unless_kept(self):
        self.make(*CLIENTS, GATE)
        r = self.run_script("uninstall-template.sh")
        self.assertEqual(r.returncode, 1)
        self.assertIn("approval gate is installed", r.stderr)
        self.assertTrue(all(self.exists(c) for c in CLIENTS), "removed despite the gate")
        r = self.run_script("uninstall-template.sh", "--keep-gate")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(any(self.exists(c) for c in CLIENTS))
        self.assertTrue(self.exists(GATE), "the gate file is not this script's to remove")

    def test_a_dangling_gate_symlink_counts(self):
        self.make(*CLIENTS)
        os.makedirs(os.path.join(self.d, os.path.dirname(GATE)))
        os.symlink("/nonexistent", os.path.join(self.d, GATE))
        self.assertEqual(self.run_script("uninstall-template.sh").returncode, 1)

    def test_foreign_files_stay(self):
        self.make(*CLIENTS, "usr/share/qvm-wormhole/local-notes.txt")
        r = self.run_script("uninstall-template.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.exists("usr/share/qvm-wormhole/local-notes.txt"))
        self.assertIn("left in place", r.stdout)

    def test_bad_argument(self):
        self.assertEqual(self.run_script("uninstall-template.sh", "--everything").returncode, 2)

    def test_dvm_handlers_removed(self):
        self.make("usr/local/etc/qubes-rpc/wormhole.Send", "usr/local/etc/qubes-rpc/wormhole.Recv",
                  "usr/local/etc/qubes-rpc/other.Service")
        r = self.run_script("qrexec/uninstall-on-dvm.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.exists("usr/local/etc/qubes-rpc/wormhole.Send"))
        self.assertFalse(self.exists("usr/local/etc/qubes-rpc/wormhole.Recv"))
        self.assertTrue(self.exists("usr/local/etc/qubes-rpc/other.Service"))


if __name__ == "__main__":
    unittest.main()
