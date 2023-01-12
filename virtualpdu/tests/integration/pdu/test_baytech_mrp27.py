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

from virtualpdu import core
from virtualpdu.pdu.baytech_mrp27 import BaytechMRP27PDU
from virtualpdu.pdu.baytech_mrp27 import BaytechMRP27PDUOutletControl
from virtualpdu.tests.integration.pdu import PDUTestCase


class TestBaytechMRP27PDU(PDUTestCase):
    pdu_class = BaytechMRP27PDU
    outlet_control_class = BaytechMRP27PDUOutletControl

    def test_all_ports_are_on_by_default(self):
        self.core_mock.get_pdu_outlet_state.return_value = core.POWER_ON

        outlet_state_oid = (1, 3, 6, 1, 4, 1) + (4779, 1, 3, 5, 3, 1, 3)

        self.assertEqual(1, self.snmp_get(outlet_state_oid + (1, 1)))
        self.assertEqual(1, self.snmp_get(outlet_state_oid + (1, 2)))
        self.assertEqual(1, self.snmp_get(outlet_state_oid + (1, 3)))
        self.assertEqual(1, self.snmp_get(outlet_state_oid + (1, 4)))
        self.assertEqual(1, self.snmp_get(outlet_state_oid + (1, 5)))
        self.assertEqual(1, self.snmp_get(outlet_state_oid + (1, 6)))
        self.assertEqual(1, self.snmp_get(outlet_state_oid + (1, 7)))
        self.assertEqual(1, self.snmp_get(outlet_state_oid + (1, 8)))
        self.assertEqual(1, self.snmp_get(outlet_state_oid + (1, 9)))
        self.assertEqual(1, self.snmp_get(outlet_state_oid + (1, 10)))

        self.assertFalse(self.core_mock.set_pdu_outlet_command.called)

    def test_port_state_can_be_changed(self):
        outlet_state_oid = (1, 3, 6, 1, 4, 1) + (4779, 1, 3, 5, 3, 1, 3)
        outlet_1 = outlet_state_oid + (1, 1)

        self.core_mock.get_pdu_outlet_state.return_value = core.POWER_ON
        self.assertEqual(self.outlet_control_class.states.ON,
                         self.snmp_get(outlet_1))

        self.snmp_set(outlet_1, self.outlet_control_class.states.OFF)
        self.core_mock.set_pdu_outlet_command.assert_called_with(
            pdu=self.pdu.name, outlet=1, command=core.POWER_OFF)

        self.core_mock.get_pdu_outlet_state.return_value = core.POWER_OFF
        self.assertEqual(self.outlet_control_class.states.OFF,
                         self.snmp_get(outlet_1))
