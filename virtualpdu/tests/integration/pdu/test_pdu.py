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

from pyasn1.type import univ
from pysnmp.proto.rfc1905 import NoSuchInstance

from virtualpdu import core
from virtualpdu import pdu
from virtualpdu.tests.integration.pdu import PDUTestCase
from virtualpdu.tests.snmp_error_indications import RequestTimedOut

enterprises = (1, 3, 6, 1, 4, 1)


class TestPDU(PDUTestCase):
    pdu_class = pdu.PDU
    outlet_control_class = pdu.PDUOutletControl

    def test_get_unknown_oid(self):
        self.assertEqual(NoSuchInstance(''),
                         self.snmp_get(enterprises + (42,)))

    def test_set_unknown_oid(self):
        self.assertEqual(NoSuchInstance(''),
                         self.snmp_set(enterprises + (42,), univ.Integer(7)))

    def test_get_valid_oid_wrong_community(self):
        self.core_mock.get_pdu_outlet_state.return_value = core.POWER_ON
        self.pdu.oid_mapping[enterprises + (88, 1)] = \
            pdu.PDUOutletControl(pdu_name=self.pdu.name,
                                 outlet_number=1,
                                 core=self.core_mock)

        self.assertEqual(self.outlet_control_class.states.ON,
                         self.snmp_get(enterprises + (88, 1)))

        self.assertRaises(RequestTimedOut,
                          self.snmp_get, enterprises + (88, 1),
                          community='wrong')

    def test_set_wrong_community(self):
        self.assertRaises(RequestTimedOut,
                          self.snmp_set, enterprises + (42,),
                          self.outlet_control_class.states.ON,
                          community='wrong')
