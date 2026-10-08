import importlib.util
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('scanner', Path(__file__).parents[1] / 'simple-network-scanner.py')
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.app = scanner.NmapGUI.__new__(scanner.NmapGUI)
        self.app.local_host_ip = ''
        self.app.output_queue = queue.Queue()
        self.app.cancel_requested = threading.Event()
        self.app.process = None
        self.app.current_xml_path = None
        self.app.current_temp_dir = None

    def test_targets(self):
        for target in ('192.168.1.1', '192.168.1.0/24', 'server.local'):
            self.assertTrue(self.app.validate_target(target))
        for target in ('::1', '2001:db8::/64', '-oX', 'host other', ''):
            self.assertFalse(self.app.validate_target(target))

    def test_missing_and_malformed_results_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'scan.xml'
            with self.assertRaises(RuntimeError):
                self.app.parse_nmap_xml(str(path))
            path.write_text('<nmaprun><host>')
            with self.assertRaises(RuntimeError):
                self.app.parse_nmap_xml(str(path))

    def test_valid_results(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'scan.xml'
            path.write_text('<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port><port protocol="tcp" portid="81"><state state="closed"/></port></ports></host></nmaprun>')
            results = self.app.parse_nmap_xml(str(path))
            self.assertEqual(len(results['devices']), 1)
            self.assertEqual([p['port'] for p in results['ports']], ['80'])

    def test_stop_escalates_after_timeout(self):
        process = Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired('nmap', 3), 0]
        self.app.request_process_stop(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()

    def test_privileged_stop_failure_is_reported(self):
        process = Mock()
        process.terminate.side_effect = PermissionError()
        self.app.cancel_requested.set()
        self.app.request_process_stop(process)
        self.assertFalse(self.app.cancel_requested.is_set())
        self.assertEqual(self.app.output_queue.get()[0], 'stop_failed')

    def test_cancel_before_launch(self):
        process = Mock(stdout=iter(()))
        process.stdout = None
        process.wait.return_value = -15
        self.app.cancel_requested.set()
        with patch.object(scanner.subprocess, 'Popen', return_value=process):
            self.app.run_scan(['nmap'], '/missing.xml', 'Device Discovery')
        process.terminate.assert_called_once()
        event, data = self.app.output_queue.get()
        self.assertEqual(event, 'scan_complete')
        self.assertEqual(data['return_code'], -15)
        self.assertIsNone(self.app.process)

    def test_detection_preserves_target_during_scan(self):
        self.app.scan_running = True
        self.app.detection_running = True
        self.app.detection_target = ''
        self.app.target_var = Mock()
        self.app.target_var.get.return_value = 'server.local'
        self.app.interface_var = Mock()
        self.app.status_var = Mock()
        self.app.detect_button = Mock()
        self.app.network_detection_success({'interface': 'eth0', 'address': '192.0.2.1', 'network': '192.0.2.0/24'})
        self.app.target_var.set.assert_not_called()
        self.app.detect_button.config.assert_not_called()

if __name__ == '__main__':
    unittest.main()
