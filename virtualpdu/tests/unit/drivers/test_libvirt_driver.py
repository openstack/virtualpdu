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

import libvirt

from virtualpdu import drivers
from virtualpdu.drivers import libvirt_driver
from virtualpdu.tests import base

DOMAIN_ALREADY_RUNNING = "internal error: Domain '{}' is already running"
DOMAIN_NOT_RUNNING = "Requested operation is not valid: domain is not running"


@mock.patch('libvirt.open', autospec=True)
class TestLibvirtDriver(base.TestCase):
    def setUp(self):
        super(TestLibvirtDriver, self).setUp()
        self.driver = libvirt_driver.LibvirtDriver(uri='hello')

    def test_power_on(self, mock_open):
        domain_mock = mock.Mock()
        connection_mock = mock.Mock()
        connection_mock.lookupByName.return_value = domain_mock
        mock_open.return_value = connection_mock

        self.driver.power_on('domainA')

        mock_open.assert_called_with('hello')
        connection_mock.lookupByName.assert_called_with('domainA')
        domain_mock.create.assert_called_with()
        connection_mock.close.assert_called_with()

    def test_power_off(self, mock_open):
        domain_mock = mock.Mock()
        connection_mock = mock.Mock()
        connection_mock.lookupByName.return_value = domain_mock
        mock_open.return_value = connection_mock

        self.driver.power_off('domainA')

        mock_open.assert_called_with('hello')
        connection_mock.lookupByName.assert_called_with('domainA')
        domain_mock.destroy.assert_called_with()
        connection_mock.close.assert_called_with()

    def test_power_off_domain_not_running(self, mock_open):
        domain_name = 'domainA'

        domain_mock = mock.Mock()
        connection_mock = mock.Mock()
        connection_mock.lookupByName.return_value = domain_mock

        domain_mock.destroy.side_effect = \
            DumbLibvirtError(DOMAIN_NOT_RUNNING,
                             conn=connection_mock)
        mock_open.return_value = connection_mock

        self.driver.power_off(domain_name)

        domain_mock.destroy.assert_called_with()
        connection_mock.close.assert_called_with()

    def test_power_off_generic_error_goes_through(self, mock_open):
        domain_mock = mock.Mock()
        connection_mock = mock.Mock()
        connection_mock.lookupByName.return_value = domain_mock

        domain_mock.destroy.side_effect = SpecificException()
        mock_open.return_value = connection_mock

        self.assertRaises(SpecificException, self.driver.power_off, 'domainA')

        connection_mock.close.assert_called_with()

    def test_get_power_state_on(self, mock_open):
        domain_mock = mock.Mock()
        domain_mock.isActive.return_value = 1
        connection_mock = mock.Mock()
        connection_mock.lookupByName.return_value = domain_mock
        mock_open.return_value = connection_mock

        self.assertEqual(drivers.POWER_ON,
                         self.driver.get_power_state('domainA'))

        mock_open.assert_called_with('hello')
        connection_mock.lookupByName.assert_called_with('domainA')
        domain_mock.isActive.assert_called_with()
        connection_mock.close.assert_called_with()

    def test_get_power_state_off(self, mock_open):
        domain_mock = mock.Mock()
        domain_mock.isActive.return_value = 0
        connection_mock = mock.Mock()
        connection_mock.lookupByName.return_value = domain_mock
        mock_open.return_value = connection_mock

        self.assertEqual(drivers.POWER_OFF,
                         self.driver.get_power_state('domainA'))

        mock_open.assert_called_with('hello')
        connection_mock.lookupByName.assert_called_with('domainA')
        domain_mock.isActive.assert_called_with()
        connection_mock.close.assert_called_with()

    def test_get_power_state_domain_not_found(self, mock_open):
        connection_mock = mock.Mock()
        connection_mock.lookupByName.side_effect = \
            libvirt.libvirtError('virDomainLookupByName() failed')
        mock_open.return_value = connection_mock

        self.assertRaises(drivers.DeviceNotFound,
                          self.driver.get_power_state, 'domainA')

        connection_mock.close.assert_called_with()

    def test_power_on_domain_not_found(self, mock_open):
        connection_mock = mock.Mock()
        connection_mock.lookupByName.side_effect = \
            libvirt.libvirtError('virDomainLookupByName() failed')
        mock_open.return_value = connection_mock

        self.assertRaises(drivers.DeviceNotFound,
                          self.driver.power_on, 'domainA')

        connection_mock.close.assert_called_with()

    def test_power_off_domain_not_found(self, mock_open):
        connection_mock = mock.Mock()
        connection_mock.lookupByName.side_effect = \
            libvirt.libvirtError('virDomainLookupByName() failed')
        mock_open.return_value = connection_mock

        self.assertRaises(drivers.DeviceNotFound,
                          self.driver.power_off, 'domainA')

        connection_mock.close.assert_called_with()

    def test_power_on_domain_already_running(self, mock_open):
        domain_name = 'domainA'

        domain_mock = mock.Mock()
        connection_mock = mock.Mock()
        connection_mock.lookupByName.return_value = domain_mock

        domain_mock.create.side_effect = \
            DumbLibvirtError(DOMAIN_ALREADY_RUNNING.format(domain_name),
                             conn=connection_mock)
        mock_open.return_value = connection_mock

        self.driver.power_on(domain_name)

        connection_mock.close.assert_called_with()

    def test_power_on_generic_error_goes_through(self, mock_open):
        domain_mock = mock.Mock()
        connection_mock = mock.Mock()
        connection_mock.lookupByName.return_value = domain_mock

        domain_mock.create.side_effect = SpecificException()
        mock_open.return_value = connection_mock

        self.assertRaises(SpecificException, self.driver.power_on, 'domainA')

        connection_mock.close.assert_called_with()


@mock.patch('libvirt.open', autospec=True)
class TestKeepaliveLibvirtDriver(base.TestCase):
    def setUp(self):
        super(TestKeepaliveLibvirtDriver, self).setUp()
        self.driver = libvirt_driver.KeepaliveLibvirtDriver(uri='hello')

    def test_power_on_stays_connected(self, mock_open):
        domain_mock = mock.Mock()
        connection_mock = mock.Mock()
        connection_mock.lookupByName.return_value = domain_mock
        mock_open.return_value = connection_mock

        self.driver.power_on('domainA')

        mock_open.assert_called_with('hello')
        connection_mock.lookupByName.assert_called_with('domainA')
        domain_mock.create.assert_called_with()
        self.assertFalse(connection_mock.close.called)


class SpecificException(Exception):
    pass


class DumbLibvirtError(libvirt.libvirtError):
    def __init__(self, defmsg, conn=None, dom=None, net=None,
                 pool=None, vol=None):
        # NOTE(walhawari): Libvirt fetches "last error" and if that
        #                  returns anything, defmsg is simply ignored.
        #                  Work around this design limitation by creating an
        #                  exception that derives from libvirtError but doesn't
        #                  have this behavior.
        Exception.__init__(self, defmsg)
