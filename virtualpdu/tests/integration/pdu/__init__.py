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

import random
from unittest import mock

from pysnmp.entity.rfc3413.oneliner import cmdgen

from virtualpdu.pdu import pysnmp_handler
from virtualpdu.tests import base
from virtualpdu.tests import snmp_client


class PDUTestCase(base.TestCase):
    pdu_class = NotImplementedError
    outlet_control_class = NotImplementedError

    def setUp(self):
        super(PDUTestCase, self).setUp()
        self.community = 'test1212'
        self.core_mock = mock.Mock()
        self.pdu = self.pdu_class(name='test_pdu', core=self.core_mock)
        self.pdu_test_harness = pysnmp_handler.SNMPPDUHarness(
            self.pdu,
            '127.0.0.1',
            random.randint(20000, 30000),
            snmp_versions=['1', '2c'],
            community=self.community)
        self.pdu_test_harness.start()

    def tearDown(self):
        self.pdu_test_harness.stop()
        super(PDUTestCase, self).tearDown()

    def snmp_get(self, oid, community=None):
        s = snmp_client.SnmpClient(cmdgen,
                                   self.pdu_test_harness.listen_address,
                                   self.pdu_test_harness.listen_port,
                                   community=community or self.community,
                                   timeout=1,
                                   retries=1)
        return s.get_one(oid)

    def snmp_get_next(self, oid, community=None):
        s = snmp_client.SnmpClient(cmdgen,
                                   self.pdu_test_harness.listen_address,
                                   self.pdu_test_harness.listen_port,
                                   community=community or self.community,
                                   timeout=1,
                                   retries=1)
        return s.get_next(oid)

    def snmp_set(self, oid, value, community=None):
        s = snmp_client.SnmpClient(cmdgen,
                                   self.pdu_test_harness.listen_address,
                                   self.pdu_test_harness.listen_port,
                                   community=community or self.community,
                                   timeout=1,
                                   retries=1)

        return s.set(oid, value)
