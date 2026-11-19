"""Private managed capture preflight. Run only in a network-none fixture."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
import sys
sys.path.insert(0, str(SCRIPTS))
import browser_provisioner as provisioner
import task_proxy_incident as incident


class CapturePreflight(unittest.TestCase):
    def test_managed_capture_must_be_private_and_held_for_write(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
            root = Path(root)
            flow = provisioner._capture_file(root / 'capture')
            identity = provisioner._capture_identity(flow)
            row = {'flow_path': str(flow), 'capture_identity': json.dumps(identity)}
            fd = os.open(flow, os.O_WRONLY)
            try:
                incident.verify_capture(row, os.getpid())
                os.chmod(flow, 0o644)
                with self.assertRaises((incident.Blocked, OSError)):
                    incident.verify_capture(row, os.getpid())
                os.chmod(flow, 0o600)
                os.chmod(flow, 0o700)
                with self.assertRaises((incident.Blocked, OSError)):
                    incident.verify_capture(row, os.getpid())
                os.chmod(flow, 0o600)
                os.chmod(flow.parent, 0o500)
                with self.assertRaises((incident.Blocked, OSError)):
                    incident.verify_capture(row, os.getpid())
                os.chmod(flow.parent, 0o700)
            finally:
                os.close(fd)
            with self.assertRaises((incident.Blocked, OSError)):
                incident.verify_capture(row, os.getpid())
            with self.assertRaises((incident.Blocked, OSError)):
                incident.verify_capture({'flow_path': None, 'capture_identity': None}, os.getpid())
