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

from unittest import mock
from unittest.mock import sentinel

from pysnmp.proto import errind
from pysnmp.proto.errind import ErrorIndication
from pysnmp.proto.rfc1905 import NoSuchInstance
import testtools

from virtualpdu.tests import base
from virtualpdu.tests import snmp_client
from virtualpdu.tests import snmp_error_indications


class TestSnmpClient(base.TestCase):
    def setUp(self):
        super(TestSnmpClient, self).setUp()
        self.command_generator_mock = mock.Mock()
        self.pysnmp_mock = mock.Mock()
        self.oneliner_cmdgen = mock.Mock()

        self.oneliner_cmdgen.CommandGenerator.return_value = \
            self.command_generator_mock

        self.oneliner_cmdgen.CommunityData.return_value = \
            sentinel.community_data

        self.oneliner_cmdgen.UdpTransportTarget.return_value = \
            sentinel.udp_transport_target

        self.snmp_client = snmp_client.SnmpClient(
            oneliner_cmdgen=self.oneliner_cmdgen,
            host=sentinel.hostname,
            port=sentinel.port,
            community=sentinel.community,
            timeout=sentinel.timeout,
            retries=sentinel.retries,
        )

        self.all_error_indications = [
            (errind.__dict__.get(a).__class__.__name__, errind.__dict__.get(a))
            for a in dir(errind)
            if isinstance(errind.__dict__.get(a), ErrorIndication)]

    def test_all_error_indications_exist(self):
        for class_name, error_indication in self.all_error_indications:
            exception_class = snmp_error_indications.__dict__.get(class_name)

            self.assertIsNotNone(exception_class,
                                 "Exception class {} was not found in "
                                 "snmp_client.".format(class_name))

            self.assertIsInstance(exception_class(),
                                  snmp_error_indications.SNMPErrorIndication,
                                  class_name)

    def test_get_one(self):
        oid = (1, 3, 6)
        self.command_generator_mock.getCmd.return_value = \
            (None, 0, 0, [(oid, '42 thousands')])
        value = self.snmp_client.get_one(oid)

        self.assertEqual('42 thousands', value)

        self.oneliner_cmdgen.UdpTransportTarget\
            .assert_called_with((sentinel.hostname, sentinel.port),
                                timeout=sentinel.timeout,
                                retries=sentinel.retries)
        self.oneliner_cmdgen.CommunityData\
            .assert_called_with(sentinel.community, mpModel=0)
        self.command_generator_mock.getCmd.assert_called_with(
            sentinel.community_data,
            sentinel.udp_transport_target,
            oid, contextEngineId=None, contextName=''
        )

    def test_get_with_all_possible_error_indications(self):
        oid = (1, 3, 6)
        for class_name, error_indication in self.all_error_indications:
            self.command_generator_mock.getCmd.return_value = \
                (error_indication, 0, 0, [])

            exception_class = snmp_error_indications.__dict__.get(class_name)

            with testtools.ExpectedException(exception_class):
                self.snmp_client.get_one(oid)

    def test_set(self):
        oid = (1, 3, 6)
        self.command_generator_mock.setCmd.return_value = \
            (None, 0, 0, [(oid, '43 thousands')])
        value = self.snmp_client.set(oid, '43 thousands')

        self.assertEqual('43 thousands', value)

        self.oneliner_cmdgen.UdpTransportTarget\
            .assert_called_with((sentinel.hostname, sentinel.port),
                                timeout=sentinel.timeout,
                                retries=sentinel.retries)
        self.oneliner_cmdgen.CommunityData\
            .assert_called_with(sentinel.community, mpModel=0)
        self.command_generator_mock.setCmd.assert_called_with(
            sentinel.community_data,
            sentinel.udp_transport_target,
            (oid, '43 thousands'),
            contextEngineId=None, contextName=''
        )

    def test_set_no_such_instance(self):
        oid = (1, 3, 6)
        self.command_generator_mock.setCmd.return_value = \
            (None, 0, 0, [(oid, NoSuchInstance(''))])
        value = self.snmp_client.set(oid, '43 thousands')

        self.assertEqual(NoSuchInstance(''), value)

        self.oneliner_cmdgen.UdpTransportTarget \
            .assert_called_with((sentinel.hostname, sentinel.port),
                                timeout=sentinel.timeout,
                                retries=sentinel.retries)

        self.oneliner_cmdgen.CommunityData \
            .assert_called_with(sentinel.community, mpModel=0)

        self.command_generator_mock.setCmd.assert_called_with(
            sentinel.community_data,
            sentinel.udp_transport_target,
            (oid, '43 thousands'),
            contextEngineId=None, contextName=''
        )

    def test_set_with_all_possible_error_indications(self):
        oid = (1, 3, 6)
        for class_name, error_indication in self.all_error_indications:
            self.command_generator_mock.setCmd.return_value = \
                (error_indication, 0, 0, [])
            exception_class = snmp_error_indications.__dict__.get(class_name)

            self.assertRaises(exception_class,
                              self.snmp_client.set, oid, 'test')
