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

import functools
from unittest import mock

from virtualpdu import core


class BasePDUTests(object):
    pdu_class = None
    outlet_control_oid = None

    @functools.cached_property
    def core_mock(self):
        return mock.Mock()

    @functools.cached_property
    def pdu(self):
        return self.pdu_class(name='my_pdu', core=self.core_mock)

    def test_power_on_notifies_core(self):
        outlet_control = self.pdu.oid_mapping[self.outlet_control_oid]
        outlet_control.value = \
            outlet_control.states.from_core(core.POWER_ON)

        self.core_mock.set_pdu_outlet_command.assert_called_with(
            pdu='my_pdu',
            outlet=1,
            command=core.POWER_ON)

    def test_reboot_notifies_core(self):
        outlet_control = self.pdu.oid_mapping[self.outlet_control_oid]
        outlet_control.value = \
            outlet_control.states.from_core(core.REBOOT)

        self.core_mock.set_pdu_outlet_command.assert_called_with(
            pdu='my_pdu',
            outlet=1,
            command=core.REBOOT)

    def test_power_off_notifies_core(self):
        outlet_control = self.pdu.oid_mapping[self.outlet_control_oid]
        outlet_control.value = \
            outlet_control.states.from_core(core.POWER_OFF)

        self.core_mock.set_pdu_outlet_command.assert_called_with(
            pdu='my_pdu',
            outlet=1,
            command=core.POWER_OFF)

    def test_read_power_on(self):
        outlet_control = self.pdu.oid_mapping[self.outlet_control_oid]
        self.core_mock.get_pdu_outlet_state.return_value = core.POWER_ON

        self.assertEqual(
            outlet_control.states.from_core(core.POWER_ON),
            outlet_control.value
        )

        self.core_mock.get_pdu_outlet_state.assert_called_with(
            pdu='my_pdu',
            outlet=1)

    def test_read_power_off(self):
        outlet_control = self.pdu.oid_mapping[self.outlet_control_oid]
        self.core_mock.get_pdu_outlet_state.return_value = core.POWER_OFF

        self.assertEqual(
            outlet_control.states.from_core(core.POWER_OFF),
            outlet_control.value
        )

        self.core_mock.get_pdu_outlet_state.assert_called_with(
            pdu='my_pdu',
            outlet=1)
