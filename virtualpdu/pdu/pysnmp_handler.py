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

import logging
import threading

from pysnmp.carrier.asynsock.dgram import udp
from pysnmp import debug
from pysnmp.entity import config
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import cmdrsp
from pysnmp.entity.rfc3413 import context
from pysnmp.proto.api import v2c

# pysnmp is distributed under the BSD license.

from virtualpdu.pdu import TraversableOidMapping


class GetCommandResponder(cmdrsp.GetCommandResponder):

    def __init__(self, snmpEngine, snmpContext, power_unit):
        super(GetCommandResponder, self).__init__(snmpEngine, snmpContext)
        self.__power_unit = power_unit

    def handleMgmtOperation(self, snmpEngine, stateReference,
                            contextName, req_pdu, acInfo):

        var_binds = []

        for oid, val in v2c.apiPDU.getVarBinds(req_pdu):
            var_binds.append(
                (oid, (self.__power_unit.oid_mapping[oid].value
                       if oid in self.__power_unit.oid_mapping
                       else v2c.NoSuchInstance('')))
            )

        self.sendRsp(snmpEngine, stateReference, 0, 0, var_binds)

        self.releaseStateInformation(stateReference)


class NextCommandResponder(cmdrsp.NextCommandResponder):

    def __init__(self, snmpEngine, snmpContext, power_unit):
        super(NextCommandResponder, self).__init__(snmpEngine, snmpContext)
        self.__power_unit = power_unit

    def handleMgmtOperation(self, snmpEngine, stateReference,
                            contextName, req_pdu, acInfo):

        oid_map = TraversableOidMapping(self.__power_unit.oid_mapping)

        var_binds = []

        for oid, val in v2c.apiPDU.getVarBinds(req_pdu):

            try:
                oid = oid_map.next(to=oid)
                val = self.__power_unit.oid_mapping[oid].value

            except (KeyError, IndexError):
                val = v2c.NoSuchInstance('')

            var_binds.append((oid, val))

        self.sendRsp(snmpEngine, stateReference, 0, 0, var_binds)

        self.releaseStateInformation(stateReference)


class SetCommandResponder(cmdrsp.SetCommandResponder):

    def __init__(self, snmpEngine, snmpContext, power_unit):
        super(SetCommandResponder, self).__init__(snmpEngine, snmpContext)
        self.__power_unit = power_unit

        self.__logger = logging.getLogger(__name__)

    def handleMgmtOperation(self, snmpEngine, stateReference,
                            contextName, req_pdu, acInfo):

        var_binds = []

        for oid, val in v2c.apiPDU.getVarBinds(req_pdu):
            if oid in self.__power_unit.oid_mapping:
                try:
                    self.__power_unit.oid_mapping[oid].value = val

                except Exception as ex:
                    self.__logger.info(
                        'Set value {} on power unit {} failed: {}'.format(
                            val, self.__power_unit.name, ex
                        )
                    )
                    val = v2c.NoSuchInstance('')
            else:
                val = v2c.NoSuchInstance('')

            var_binds.append((oid, val))

        self.sendRsp(snmpEngine, stateReference, 0, 0, var_binds)

        self.releaseStateInformation(stateReference)


def create_snmp_engine(power_unit, listen_address, listen_port,
                       community="public"):
    snmp_engine = engine.SnmpEngine()

    config.addSocketTransport(
        snmp_engine,
        udp.domainName,
        udp.UdpTransport().openServerMode((listen_address, listen_port))
    )

    config.addV1System(snmp_engine, community, community)

    # Allow read MIB access for this user / securityModels at SNMP VACM
    for snmp_version in (1, 2):
        config.addVacmUser(snmp_engine, snmp_version,
                           community, 'noAuthNoPriv', (1,), (1,))

    snmp_context = context.SnmpContext(snmp_engine)

    # Register SNMP Apps at the SNMP engine for particular SNMP context
    GetCommandResponder(snmp_engine, snmp_context, power_unit=power_unit)
    NextCommandResponder(snmp_engine, snmp_context, power_unit=power_unit)
    SetCommandResponder(snmp_engine, snmp_context, power_unit=power_unit)

    return snmp_engine


class SNMPPDUHarness(threading.Thread):
    def __init__(self, power_unit,
                 listen_address, listen_port,
                 community="public",
                 debug_snmp=False):
        super(SNMPPDUHarness, self).__init__()

        self._logger = logging.getLogger(__name__)

        if debug_snmp:
            debug.setLogger(debug.Debug('all'))

        self.snmp_engine = create_snmp_engine(power_unit, listen_address,
                                              listen_port, community)

        self.listen_address = listen_address
        self.listen_port = listen_port
        self.power_unit = power_unit

        self._lock = threading.Lock()
        self._stop_requested = False

    def run(self):
        with self._lock:
            if self._stop_requested:
                return

            self._logger.info("Starting SNMP agent at {}:{} serving '{}'"
                              .format(self.listen_address, self.listen_port,
                                      self.power_unit.name))

            self.snmp_engine.transportDispatcher.jobStarted(1)

        try:
            # Dispatcher will never finish as job#1 never reaches zero
            self.snmp_engine.transportDispatcher.runDispatcher()

        except Exception:
            self.snmp_engine.transportDispatcher.closeDispatcher()

    def stop(self):
        with self._lock:
            self._stop_requested = True
            try:
                self.snmp_engine.transportDispatcher.jobFinished(1)

            except KeyError:
                pass  # The job is not started yet and will not start
