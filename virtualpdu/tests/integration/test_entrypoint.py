# Copyright 2016 Internap
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import signal
import subprocess
import sys
import tempfile
import threading

from pysnmp.entity.rfc3413.oneliner import cmdgen
from retrying import retry

from virtualpdu.pdu import apc_rackpdu
from virtualpdu.pdu.apc_rackpdu import APCRackPDUOutletControl
from virtualpdu.tests import base
from virtualpdu.tests import snmp_client

TEST_CONFIG = """[global]
libvirt_uri=test:///default

[my_pdu]
listen_address=127.0.0.1
listen_port=9998
snmp_versions=1
community=public
ports=5:test

[my_second_pdu]
listen_address=127.0.0.1
listen_port=9997
snmp_versions=1
community=public
ports=2:test
"""


class TestEntryPointIntegration(base.TestCase):
    def test_entry_point_works(self):
        p = subprocess.Popen([
            sys.executable, _get_entry_point_path('virtualpdu')],
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        self.assertIn(
            b'Missing configuration file as first parameter.\n',
            stderr)
        self.assertEqual(1, p.returncode)

    def test_config(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(bytearray(TEST_CONFIG, encoding='utf-8'))
            f.flush()
            try:
                p = subprocess.Popen([
                    sys.executable,
                    _get_entry_point_path('virtualpdu'),
                    f.name,
                ])

                _turn_off_outlet(community='public',
                                 listen_address='127.0.0.1',
                                 outlet=5,
                                 port=9998)

                _turn_off_outlet(community='public',
                                 listen_address='127.0.0.1',
                                 outlet=2,
                                 port=9997)
            finally:
                # NOTE(mmitchell): The process shouldn't have died on it's
                #                  own. Kill it.
                p.kill()

    def test_sigint_stops_the_process(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(bytearray(TEST_CONFIG, encoding='utf-8'))
            f.flush()
            try:
                p = subprocess.Popen([
                    sys.executable,
                    _get_entry_point_path('virtualpdu'),
                    f.name,
                ])
                self.assertIsNone(p.poll())
                p.send_signal(signal.SIGINT)
                self._poll_process_for_done(p)
            finally:
                try:
                    p.kill()
                except OSError:
                    pass

    def test_pdu_names_ips_and_ports_are_shown_on_stderr(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(bytearray(TEST_CONFIG, encoding='utf-8'))
            f.flush()
            try:
                p = subprocess.Popen([
                    sys.executable,
                    _get_entry_point_path('virtualpdu'),
                    f.name,
                ], stderr=subprocess.PIPE)

                t = threading.Timer(1, p.send_signal, [signal.SIGINT])
                t.start()
                stdout, stderr = p.communicate()
                t.join()

                self.assertIn(b'my_pdu', stderr)
                self.assertIn(b'127.0.0.1:9998', stderr)

                self.assertIn(b'my_second_pdu', stderr)
                self.assertIn(b'127.0.0.1:9997', stderr)
            finally:
                try:
                    p.kill()
                except OSError:
                    pass

    def test_entrypoint_raise_on_invalid_mode(self):
        with tempfile.NamedTemporaryFile() as f:
            test_config2 = """[global]
libvirt_uri=test:///default
outlet_default_state = invalid_mode
"""
            f.write(bytearray(test_config2, encoding='utf-8'))
            f.flush()
            try:
                p = subprocess.Popen([
                    sys.executable,
                    _get_entry_point_path('virtualpdu'),
                    f.name,
                ], stderr=subprocess.PIPE)

                stdout, stderr = p.communicate()
                self.assertEqual(1, p.returncode)
                self.assertIn(b'invalid_mode', stderr)
                self._poll_process_for_done(p)
            finally:
                try:
                    p.kill()
                except OSError:
                    pass

    @retry(stop_max_attempt_number=10, wait_fixed=1000)
    def _poll_process_for_done(self, process):
        return self.assertIsNotNone(process.poll())


def _turn_off_outlet(community, listen_address, outlet, port):
    outlet_oid = apc_rackpdu.rPDU_outlet_control_outlet_command + (outlet,)
    snmp_client_ = snmp_client.SnmpClient(cmdgen,
                                          listen_address,
                                          port,
                                          community=community,
                                          timeout=1,
                                          retries=1)

    snmp_client_.set(outlet_oid, APCRackPDUOutletControl.states.IMMEDIATE_OFF)


def _get_entry_point_path(entry_point):
    return os.path.join(os.path.dirname(sys.executable), entry_point)
