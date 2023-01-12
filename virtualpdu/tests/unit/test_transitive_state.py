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

import threading
from unittest import mock

from virtualpdu import core
from virtualpdu import drivers
from virtualpdu.tests import base


class TestTransitiveState(base.TestCase):
    def setUp(self):
        super(TestTransitiveState, self).setUp()
        self.driver_mock = mock.create_autospec(drivers.Driver)
        mapping = {
            ('my_pdu', 1): 'server_one'
        }
        self.store = {}
        self.core = core.Core(driver=self.driver_mock, mapping=mapping,
                              store=self.store, default_state=core.POWER_ON)

    def _set_flag_and_yield(self, threading_event):
        threading_event.set()
        self.core.executor.shutdown(True)

    def test_transitive_state_is_off_when_power_off(self):
        self.driver_mock.get_power_state.return_value = drivers.POWER_ON
        driver_can_continue = threading.Event()
        self.driver_mock.power_off.side_effect = \
            lambda _: driver_can_continue.wait()

        self.core.set_pdu_outlet_command(pdu='my_pdu',
                                         outlet=1,
                                         command=core.POWER_OFF)

        self.assertEqual(
            self.core.get_pdu_outlet_state(pdu='my_pdu', outlet=1),
            core.POWER_OFF)

        self._set_flag_and_yield(driver_can_continue)
        self.assertEqual(
            self.core.get_pdu_outlet_state(pdu='my_pdu', outlet=1),
            core.POWER_OFF)

    def test_transitive_state_is_on_when_power_on(self):
        self.driver_mock.get_power_state.return_value = drivers.POWER_OFF
        driver_can_continue = threading.Event()
        self.driver_mock.power_on.side_effect = \
            lambda _: driver_can_continue.wait()

        self.core.set_pdu_outlet_command(pdu='my_pdu',
                                         outlet=1,
                                         command=core.POWER_ON)

        self.assertEqual(
            self.core.get_pdu_outlet_state(pdu='my_pdu', outlet=1),
            core.POWER_ON)

        self._set_flag_and_yield(driver_can_continue)
        self.assertEqual(
            self.core.get_pdu_outlet_state(pdu='my_pdu', outlet=1),
            core.POWER_ON)

    def test_transitive_state_is_on_when_reboot(self):
        def assert_transitive_state_is_on(_):
            self.assertEqual(
                self.core.get_pdu_outlet_state(pdu='my_pdu', outlet=1),
                core.POWER_ON)
        self.driver_mock.power_on.side_effect = assert_transitive_state_is_on

        self.core.set_pdu_outlet_command(pdu='my_pdu',
                                         outlet=1,
                                         command=core.REBOOT)

        self.core.executor.shutdown(True)

        self.assertEqual(
            self.core.get_pdu_outlet_state(pdu='my_pdu', outlet=1),
            core.POWER_ON)
