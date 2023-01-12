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

from virtualpdu import core
from virtualpdu.pdu import apc_rackpdu
from virtualpdu.pdu import sysDescr
from virtualpdu.pdu import sysObjectID
from virtualpdu.tests import base
from virtualpdu.tests.unit.pdu.base_pdu_test_cases import BasePDUTests


class TestAPCRackPDU(base.TestCase, BasePDUTests):
    pdu_class = apc_rackpdu.APCRackPDU
    outlet_control_class = apc_rackpdu.APCRackPDUOutletControl
    outlet_control_oid = \
        apc_rackpdu.rPDU_outlet_control_outlet_command \
        + (apc_rackpdu.APCRackPDU.outlet_index_start,)
    outlet_name_oid = \
        apc_rackpdu.rPDU_outlet_config_outlet_name \
        + (apc_rackpdu.APCRackPDU.outlet_index_start,)
    outlet_config_index_oid = \
        apc_rackpdu.rPDU_outlet_config_index \
        + (apc_rackpdu.APCRackPDU.outlet_index_start,)
    outlet_state_oid = \
        apc_rackpdu.rPDU_outlet_status_outlet_state \
        + (apc_rackpdu.APCRackPDU.outlet_index_start,)

    def test_read_outlet_name(self):
        outlet_name = self.pdu.oid_mapping[self.outlet_name_oid]

        self.assertEqual(
            univ.OctetString('Outlet #1'),
            outlet_name.value
        )

    def test_read_outlet_config_index(self):
        outlet_index = self.pdu.oid_mapping[self.outlet_config_index_oid]

        self.assertEqual(
            univ.Integer(1),
            outlet_index.value
        )

    def test_read_system_description(self):
        self.assertEqual(
            univ.OctetString("APC Rack PDU (virtualpdu)"),
            self.pdu.oid_mapping[sysDescr].value
        )

    def test_read_system_oid(self):
        self.assertEqual(
            univ.ObjectIdentifier(apc_rackpdu.rPDU_sysObjectID),
            self.pdu.oid_mapping[sysObjectID].value
        )

    def test_read_load_status_load(self):
        self.assertEqual(
            univ.Integer(apc_rackpdu.amp_10),
            self.pdu.oid_mapping[apc_rackpdu.rPDU_load_status_load].value
        )

    def test_read_load_status_load_state(self):
        self.assertEqual(
            univ.Integer(apc_rackpdu.phase_load_normal),
            self.pdu.oid_mapping[apc_rackpdu.rPDU_load_status_load_state].value
        )

    def test_read_state_power_on(self):
        outlet_control = self.pdu.oid_mapping[self.outlet_state_oid]
        self.core_mock.get_pdu_outlet_state.return_value = core.POWER_ON

        self.assertEqual(
            outlet_control.states.from_core(core.POWER_ON),
            outlet_control.value
        )

        self.core_mock.get_pdu_outlet_state.assert_called_with(
            pdu='my_pdu',
            outlet=1)

    def test_read_state_power_off(self):
        outlet_control = self.pdu.oid_mapping[self.outlet_state_oid]
        self.core_mock.get_pdu_outlet_state.return_value = core.POWER_OFF

        self.assertEqual(
            outlet_control.states.from_core(core.POWER_OFF),
            outlet_control.value
        )

        self.core_mock.get_pdu_outlet_state.assert_called_with(
            pdu='my_pdu',
            outlet=1)

    def test_as_many_outlets_as_specified_by_constructor(self):
        pdu = self.pdu_class(name='test_pdu',
                             core=self.core_mock,
                             outlet_count=10)
        self.assertEqual(10, pdu.outlet_count)
        self.assertEqual(10, len([oid for oid in pdu.oid_mapping.values()
                                  if type(oid) is self.outlet_control_class]))

    def test_as_many_outlets_as_specified_by_type(self):
        self.assertEqual(self.pdu_class.outlet_count, self.pdu.outlet_count)
        self.assertEqual(self.pdu_class.outlet_count,
                         len([oid for oid in self.pdu.oid_mapping.values()
                              if type(oid) is self.outlet_control_class]))
