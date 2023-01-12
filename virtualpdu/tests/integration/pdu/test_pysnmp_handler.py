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

from random import randint
from unittest import mock

from pyasn1.type import univ
from pysnmp.entity.rfc3413.oneliner import cmdgen

from virtualpdu.pdu import pysnmp_handler
from virtualpdu.tests import base
from virtualpdu.tests import snmp_client


# TODO(mmitchell): Merge with test_pdu.py, or the other way around.
class TestSNMPPDUHarness(base.TestCase):

    def test_harness_get(self):

        mock_power_unit = mock.Mock()
        port = randint(20000, 30000)

        harness = pysnmp_handler.SNMPPDUHarness(power_unit=mock_power_unit,
                                                listen_address='127.0.0.1',
                                                listen_port=port,
                                                snmp_versions=['1', '2c'],
                                                community='bleh')

        harness.start()

        client = snmp_client.SnmpClient(oneliner_cmdgen=cmdgen,
                                        host='127.0.0.1',
                                        port=port,
                                        community='bleh',
                                        timeout=1,
                                        retries=1)

        mock_power_unit.oid_mapping = dict()
        mock_power_unit.oid_mapping[(1, 3, 6, 99)] = mock.Mock()
        mock_power_unit.oid_mapping[(1, 3, 6, 99)].value = univ.Integer(42)

        self.assertEqual(42, client.get_one((1, 3, 6, 99)))

        harness.stop()

    def test_harness_set(self):

        mock_power_unit = mock.Mock()
        port = randint(20000, 30000)
        harness = pysnmp_handler.SNMPPDUHarness(power_unit=mock_power_unit,
                                                listen_address='127.0.0.1',
                                                listen_port=port,
                                                snmp_versions=['1', '2c'],
                                                community='bleh')

        harness.start()

        client = snmp_client.SnmpClient(oneliner_cmdgen=cmdgen,
                                        host='127.0.0.1',
                                        port=port,
                                        community='bleh',
                                        timeout=1,
                                        retries=1)

        mock_power_unit.oid_mapping = dict()
        mock_power_unit.oid_mapping[(1, 3, 6, 98)] = mock.Mock()

        client.set((1, 3, 6, 98), univ.Integer(99))

        self.assertEqual(univ.Integer(99),
                         mock_power_unit.oid_mapping[(1, 3, 6, 98)].value)

        harness.stop()

    def test_harness_get_next(self):
        mock_power_unit = mock.Mock()
        port = randint(20000, 30000)
        harness = pysnmp_handler.SNMPPDUHarness(power_unit=mock_power_unit,
                                                listen_address='127.0.0.1',
                                                listen_port=port,
                                                snmp_versions=['1', '2c'],
                                                community='bleh')

        harness.start()

        client = snmp_client.SnmpClient(oneliner_cmdgen=cmdgen,
                                        host='127.0.0.1',
                                        port=port,
                                        community='bleh',
                                        timeout=1,
                                        retries=1)

        mock_power_unit.oid_mapping = dict()
        mock_power_unit.oid_mapping[(1, 3, 6, 1, 5)] = mock.Mock()
        mock_power_unit.oid_mapping[(1, 3, 6, 1, 5)].value = univ.Integer(42)

        oid, val = client.get_next((1, 3, 6, 1))

        self.assertEqual((1, 3, 6, 1, 5), oid)
        self.assertEqual(42, val)

        harness.stop()

    def test_start_stop_threadsafety(self):
        mock_power_unit = mock.Mock()
        port = randint(20000, 30000)
        harness = pysnmp_handler.SNMPPDUHarness(power_unit=mock_power_unit,
                                                listen_address='127.0.0.1',
                                                listen_port=port,
                                                snmp_versions=['1', '2c'],
                                                community='bleh')

        harness.start()
        harness.stop()
        harness.join(timeout=5)

        self.assertFalse(harness.is_alive())


class TestSNMPv3Operations(base.TestCase):

    def setUp(self):
        super(TestSNMPv3Operations, self).setUp()

        self.mock_power_unit = mock.Mock()
        self.mock_power_unit.oid_mapping = dict()
        oid = (1, 3, 6, 99)
        self.mock_power_unit.oid_mapping[oid] = mock.Mock()
        self.mock_power_unit.oid_mapping[oid].value = univ.Integer(42)

    def test_harness_none_none(self):

        port = randint(20000, 30000)

        harness = pysnmp_handler.SNMPPDUHarness(
            power_unit=self.mock_power_unit,
            listen_address='127.0.0.1',
            listen_port=port,
            snmp_versions=['3'],
            user='openstack'
        )

        harness.start()

        client = snmp_client.SnmpClient(
            oneliner_cmdgen=cmdgen,
            host='127.0.0.1',
            port=port,
            user='openstack',
            timeout=1,
            retries=1
        )

        self.assertEqual(42, client.get_one((1, 3, 6, 99)))

        harness.stop()

    def test_harness_md5_none(self):

        port = randint(20000, 30000)

        harness = pysnmp_handler.SNMPPDUHarness(
            power_unit=self.mock_power_unit,
            snmp_versions=['3'],
            listen_address='127.0.0.1',
            listen_port=port,
            user='openstack',
            auth_key='secretkey',
            auth_protocol='MD5'
        )

        harness.start()

        client = snmp_client.SnmpClient(
            oneliner_cmdgen=cmdgen,
            host='127.0.0.1',
            port=port,
            user='openstack',
            auth_key='secretkey',
            auth_protocol='MD5',
            timeout=1,
            retries=1
        )

        self.assertEqual(42, client.get_one((1, 3, 6, 99)))

        harness.stop()

    def test_harness_md5_des(self):

        port = randint(20000, 30000)

        harness = pysnmp_handler.SNMPPDUHarness(
            power_unit=self.mock_power_unit,
            listen_address='127.0.0.1',
            listen_port=port,
            snmp_versions=['3'],
            user='openstack',
            auth_key='secretkey',
            auth_protocol='MD5',
            priv_key='secretkey',
            priv_protocol='DES'
        )

        harness.start()

        client = snmp_client.SnmpClient(
            oneliner_cmdgen=cmdgen,
            host='127.0.0.1',
            port=port,
            user='openstack',
            auth_key='secretkey',
            auth_protocol='MD5',
            priv_key='secretkey',
            priv_protocol='DES',
            timeout=1,
            retries=1
        )

        self.assertEqual(42, client.get_one((1, 3, 6, 99)))

        harness.stop()
