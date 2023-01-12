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

from pysnmp.proto.api import v2c

from virtualpdu.pdu.pysnmp_handler import auth_protocols
from virtualpdu.pdu.pysnmp_handler import priv_protocols
from virtualpdu.tests import snmp_error_indications


class SnmpClient(object):
    def __init__(self, oneliner_cmdgen, host, port, **snmp_options):
        self.host = host
        self.port = port
        self.snmp_version = snmp_options.get('snmp_version')

        # SNMPv1/v2c options
        self.community = snmp_options.get('community')

        # SNMPv3 options
        self.context_engine_id = snmp_options.get('context_engine_id')
        if self.context_engine_id:
            self.context_engine_id = v2c.OctetString(
                hexValue=self.context_engine_id
            )
        self.context_name = snmp_options.get('context_name', '')
        self.user = snmp_options.get('user')
        self.auth_key = snmp_options.get('auth_key')
        self.auth_protocol = auth_protocols[snmp_options.get('auth_protocol')
                                            or 'NONE']
        self.priv_key = snmp_options.get('priv_key')
        self.priv_protocol = priv_protocols[snmp_options.get('priv_protocol')
                                            or 'NONE']

        self.timeout = snmp_options.get('timeout')
        self.retries = snmp_options.get('retries')

        if self.snmp_version is None:
            if self.user is not None:
                self.snmp_version = 3
            else:
                self.snmp_version = 0

        cmdgen = oneliner_cmdgen

        self.command_generator = cmdgen.CommandGenerator()

        if self.snmp_version < 3:
            self.auth_data = cmdgen.CommunityData(
                self.community, mpModel=self.snmp_version
            )
        else:
            self.auth_data = cmdgen.UsmUserData(
                self.user,
                self.auth_key, self.priv_key,
                self.auth_protocol, self.priv_protocol
            )

        self.transport = cmdgen.UdpTransportTarget((self.host, self.port),
                                                   timeout=self.timeout,
                                                   retries=self.retries)

    def get_one(self, oid):
        (error_indication,
         error_status,
         error_index,
         var_binds) = self.command_generator.getCmd(
            self.auth_data, self.transport, oid,
            contextEngineId=self.context_engine_id,
            contextName=self.context_name
        )

        self._handle_error_indication(error_indication)

        name, val = var_binds[0]
        return val

    def get_next(self, oid):
        (error_indication,
         error_status,
         error_index,
         var_binds) = self.command_generator.nextCmd(
            self.auth_data, self.transport, oid,
            contextEngineId=self.context_engine_id,
            contextName=self.context_name
        )

        self._handle_error_indication(error_indication)
        for varBindTableRow in var_binds:
            for name, val in varBindTableRow:
                return name, val

    def set(self, oid, value):
        (error_indication,
         error_status,
         error_index,
         var_binds) = self.command_generator.setCmd(
            self.auth_data, self.transport, (oid, value),
            contextEngineId=self.context_engine_id,
            contextName=self.context_name
        )

        self._handle_error_indication(error_indication)

        name, val = var_binds[0]
        return val

    def _handle_error_indication(self, error_indication):
        if error_indication:
            raise snmp_error_indications.__dict__.get(
                error_indication.__class__.__name__)()
