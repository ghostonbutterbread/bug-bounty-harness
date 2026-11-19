"""Review regressions; run inside an isolated network-none container."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/task_proxy_incident.py'
spec = importlib.util.spec_from_file_location('incident_review', SCRIPT)
incident = importlib.util.module_from_spec(spec)
spec.loader.exec_module(incident)
PEM = b'-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n'


class ReviewRegressions(unittest.TestCase):
    def test_publication_does_not_replace_existing_record(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / 'private'
            fd = incident.private_directory(directory)
            self.addCleanup(os.close, fd)
            incident.publish(fd, directory, 'i.json', {'version': 1})
            with self.assertRaises(FileExistsError):
                incident.publish(fd, directory, 'i.json', {'version': 2})
            self.assertEqual(incident.read_record(fd, 'i.json'), {'version': 1})
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ['i.json'])

    def test_multiple_pem_certificates_are_rejected(self):
        with self.assertRaises(incident.Blocked):
            incident.sample({'port': 9000, '_ca_data': PEM + PEM})

    def test_published_record_is_readable_during_publication(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / 'private'
            fd = incident.private_directory(directory)
            self.addCleanup(os.close, fd)
            real_link = os.link
            def observe(*args, **kwargs):
                real_link(*args, **kwargs)
                self.assertEqual(incident.read_record(fd, 'i.json'), {'version': 1})
            with mock.patch.object(incident.os, 'link', side_effect=observe):
                incident.publish(fd, directory, 'i.json', {'version': 1})
            self.assertEqual(incident.read_record(fd, 'i.json'), {'version': 1})

    def test_publication_rejects_insecure_parent(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o777)
            with self.assertRaises(incident.Blocked):
                fd = incident.private_directory(Path(root) / 'private')
                os.close(fd)

    def test_trust_loads_snapshot_bytes_not_reopened_path(self):
        context = mock.MagicMock()
        context.cert_store_stats.return_value = {'x509_ca': 1, 'x509': 1}
        conn = mock.MagicMock()
        conn.getresponse.return_value.status = 200
        conn.getresponse.return_value.read.return_value = b'8.8.8.8'
        with mock.patch.object(incident.ssl, 'SSLContext', return_value=context), \
             mock.patch.object(incident.http.client, 'HTTPSConnection', return_value=conn):
            incident.sample({'port': 9000, 'ca': '/replaced', '_ca_data': PEM})
        context.load_verify_locations.assert_called_once_with(cadata=PEM.decode())

    def test_nonpublic_response_is_not_a_public_ip_observation(self):
        context = mock.MagicMock()
        context.cert_store_stats.return_value = {'x509_ca': 1, 'x509': 1}
        conn = mock.MagicMock()
        conn.getresponse.return_value.status = 200
        conn.getresponse.return_value.read.return_value = b'127.0.0.1'
        with mock.patch.object(incident.ssl, 'SSLContext', return_value=context), \
             mock.patch.object(incident.http.client, 'HTTPSConnection', return_value=conn):
            with self.assertRaises(incident.Blocked):
                incident.sample({'port': 9000, 'ca': '/unused', '_ca_data': PEM})

if __name__ == '__main__':
    unittest.main()
