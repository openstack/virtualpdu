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

from contextlib import closing

import libvirt

from virtualpdu import device_provider

DOMAIN_NOT_FOUND_MESSAGES = ['virDomainLookupByName() failed',
                             'Domain not found']


class LibvirtDeviceProvider(device_provider.DeviceProvider):
    def __init__(self, uri):
        self.uri = uri

    def power_on(self, name):
        with self._connect() as connection:
            domain = safe_lookup_by_name(connection, name)
            try:
                domain.create()
            except libvirt.libvirtError as e:
                if 'is already running' not in str(e):
                    raise

    def power_off(self, name):
        with self._connect() as connection:
            domain = safe_lookup_by_name(connection, name)
            domain.destroy()

    def _connect(self):
        return closing(libvirt.open(self.uri))


def safe_lookup_by_name(connection, name):
    try:
        domain = connection.lookupByName(name)
    except libvirt.libvirtError as e:
        if any([m for m in DOMAIN_NOT_FOUND_MESSAGES if m in str(e)]):
            raise LibvirtDomainNotFound()
    else:
        return domain


class LibvirtDomainNotFound(device_provider.DeviceNotFound):
    pass
