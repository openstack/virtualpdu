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

import time
from unittest import mock

from virtualpdu import core
from virtualpdu import drivers
from virtualpdu.tests import base


class TestCore(base.TestCase):
    def setUp(self):
        super(TestCore, self).setUp()
        self.driver_mock = mock.create_autospec(drivers.Driver)

        mapping = {
            ('my_pdu', 1): 'server_one'
        }

        self.store = {}
        self.core = core.Core(driver=self.driver_mock, mapping=mapping,
                              store=self.store, default_state=core.POWER_ON)

    def test_set_pdu_outlet_command_on_power_off(self):
        self.core.set_pdu_outlet_command(pdu='my_pdu',
                                         outlet=1,
                                         command=core.POWER_OFF)
        time.sleep(0.1)
        self.driver_mock.power_off.assert_called_with('server_one')

    def test_set_pdu_outlet_command_machine_not_in_mapping_noop(self):
        self.core.set_pdu_outlet_command(pdu='my_pdu',
                                         outlet=2,
                                         command=core.POWER_OFF)

        self.assertFalse(self.driver_mock.power_off.called)
        self.assertFalse(self.driver_mock.power_on.called)

    def test_set_pdu_outlet_command_on_power_on(self):
        self.core.set_pdu_outlet_command(pdu='my_pdu',
                                         outlet=1,
                                         command=core.POWER_ON)
        time.sleep(0.1)
        self.driver_mock.power_on.assert_called_with('server_one')

    def test_set_pdu_outlet_command_on_reboot(self):
        self.core.set_pdu_outlet_command(pdu='my_pdu',
                                         outlet=1,
                                         command=core.REBOOT)
        time.sleep(0.1)
        self.driver_mock.assert_has_calls([mock.call.power_off('server_one'),
                                           mock.call.power_on('server_one')])

    def test_set_pdu_outlet_command_on_reboot_will_set_state_on(self):
        self.core.set_pdu_outlet_command(pdu='my_pdu',
                                         outlet=1,
                                         command=core.REBOOT)
        self.assertEqual(
            core.POWER_ON,
            self.core.get_pdu_outlet_state(pdu='my_pdu', outlet=1))

    def test_pdu_outlet_state_on_cached_state(self):
        self.store[('my_pdu', 1)] = core.POWER_OFF
        self.assertEqual(
            core.POWER_OFF,
            self.core.get_pdu_outlet_state(pdu='my_pdu', outlet=1))

    def test_pdu_outlet_state_on_connected_device(self):
        self.driver_mock.get_power_state.return_value = core.POWER_OFF
        self.assertEqual(
            core.POWER_OFF,
            self.core.get_pdu_outlet_state(pdu='my_pdu', outlet=1))
        self.driver_mock.get_power_state.assert_called_with('server_one')

    def test_pdu_outlet_state_on_disconnected_outlet(self):
        self.assertEqual(
            core.POWER_ON,
            self.core.get_pdu_outlet_state(pdu='my_pdu', outlet=2))
