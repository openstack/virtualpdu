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


auth_protocols = {
    'MD5': config.usmHMACMD5AuthProtocol,
    'SHA': config.usmHMACSHAAuthProtocol,
    'NONE': config.usmNoAuthProtocol
}

# Some auth protocols may not be available in older pysnmp versions

try:
    auth_protocols['SHA224'] = config.usmHMAC128SHA224AuthProtocol
    auth_protocols['SHA256'] = config.usmHMAC192SHA256AuthProtocol
    auth_protocols['SHA384'] = config.usmHMAC256SHA384AuthProtocol
    auth_protocols['SHA512'] = config.usmHMAC384SHA512AuthProtocol

except AttributeError:
    pass

priv_protocols = {
    'DES': config.usmDESPrivProtocol,
    '3DES': config.usm3DESEDEPrivProtocol,
    'AES': config.usmAesCfb128Protocol,
    'AES128': config.usmAesCfb128Protocol,
    'AES192': config.usmAesCfb192Protocol,
    'AES256': config.usmAesCfb256Protocol,
    'NONE': config.usmNoPrivProtocol
}

# Some privacy protocols may not be available in older pysnmp versions

try:
    priv_protocols['AES192BLMT'] = config.usmAesBlumenthalCfb192Protocol
    priv_protocols['AES256BLMT'] = config.usmAesBlumenthalCfb256Protocol

except AttributeError:
    pass


class GetCommandResponder(cmdrsp.GetCommandResponder):

    def __init__(self, snmpEngine, snmpContext, context_name, power_unit):
        super(GetCommandResponder, self).__init__(snmpEngine, snmpContext)
        self.__context_name = v2c.OctetString(context_name)
        self.__power_unit = power_unit

    def handleMgmtOperation(self, snmpEngine, stateReference,
                            contextName, req_pdu, acInfo):

        if self.__context_name == contextName:

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

    def __init__(self, snmpEngine, snmpContext, context_name, power_unit):
        super(NextCommandResponder, self).__init__(snmpEngine, snmpContext)
        self.__context_name = v2c.OctetString(context_name)
        self.__power_unit = power_unit

    def handleMgmtOperation(self, snmpEngine, stateReference,
                            contextName, req_pdu, acInfo):

        if self.__context_name == contextName:

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

    def __init__(self, snmpEngine, snmpContext, context_name, power_unit):
        super(SetCommandResponder, self).__init__(snmpEngine, snmpContext)
        self.__context_name = v2c.OctetString(context_name)
        self.__power_unit = power_unit

        self.__logger = logging.getLogger(__name__)

    def handleMgmtOperation(self, snmpEngine, stateReference,
                            contextName, req_pdu, acInfo):

        if self.__context_name == contextName:

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


def create_snmp_engine(power_unit,
                       listen_address, listen_port,
                       **snmp_options):

    snmp_versions = snmp_options.get('snmp_versions', [])
    community = snmp_options.get('community')
    engine_id = snmp_options.get('engine_id')
    if engine_id:
        engine_id = v2c.OctetString(hexValue=engine_id)
    context_engine_id = snmp_options.get('context_engine_id')
    if context_engine_id:
        context_engine_id = v2c.OctetString(hexValue=context_engine_id)
    context_name = snmp_options.get('context_name', '')
    user = snmp_options.get('user')
    auth_key = snmp_options.get('auth_key')
    auth_protocol = auth_protocols[snmp_options.get('auth_protocol') or 'NONE']
    priv_key = snmp_options.get('priv_key')
    priv_protocol = priv_protocols[snmp_options.get('priv_protocol') or 'NONE']

    snmp_engine = engine.SnmpEngine(snmpEngineID=engine_id)

    config.addSocketTransport(
        snmp_engine,
        udp.domainName,
        udp.UdpTransport().openServerMode((listen_address, listen_port))
    )

    # SNMPv1
    if '1' in snmp_versions:
        config.addV1System(snmp_engine, community, community)

        # Allow read MIB access for this user / securityModels at SNMP VACM
        config.addVacmUser(snmp_engine, 1,
                           community, 'noAuthNoPriv', (1,), (1,))

    # SNMPv1
    if '2c' in snmp_versions:
        config.addV1System(snmp_engine, community, community)

        # Allow read MIB access for this user / securityModels at SNMP VACM
        config.addVacmUser(snmp_engine, 2,
                           community, 'noAuthNoPriv', (1,), (1,))

    # SNMPv3/USM setup

    if '3' in snmp_versions:
        config.addV3User(
            snmp_engine, user,
            auth_protocol, auth_key,
            priv_protocol, priv_key
        )

        if (auth_protocol != config.usmNoAuthProtocol
                and priv_protocol != config.usmNoPrivProtocol):
            sec_level = 'authPriv'
        elif priv_protocol != config.usmNoAuthProtocol:
            sec_level = 'authNoPriv'
        else:
            sec_level = 'noAuthNoPriv'

        config.addVacmUser(snmp_engine, 3,
                           user, sec_level, (1,), (1,))

        # SNMP context name is not actually used because we intercept
        # MIB management calls by overriding `handleMgmtOperation()`
        snmp_context = context.SnmpContext(snmp_engine,
                                           contextEngineId=context_engine_id)

    else:
        snmp_context = context.SnmpContext(snmp_engine)

    # Register SNMP Apps at the SNMP engine for particular SNMP context
    GetCommandResponder(snmp_engine, snmp_context,
                        context_name=context_name, power_unit=power_unit)
    NextCommandResponder(snmp_engine, snmp_context,
                         context_name=context_name, power_unit=power_unit)
    SetCommandResponder(snmp_engine, snmp_context,
                        context_name=context_name, power_unit=power_unit)

    return snmp_engine


class SNMPPDUHarness(threading.Thread):
    def __init__(self, power_unit,
                 listen_address, listen_port,
                 **snmp_options):

        super(SNMPPDUHarness, self).__init__()

        self._logger = logging.getLogger(__name__)

        if snmp_options.get('debug_snmp'):
            debug.setLogger(debug.Debug('all'))

        self.snmp_engine = create_snmp_engine(
            power_unit,
            listen_address, listen_port,
            **snmp_options
        )

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
