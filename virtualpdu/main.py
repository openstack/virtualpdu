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
import sys

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

import virtualpdu.core
from virtualpdu.drivers import libvirt_driver
from virtualpdu.pdu import apc_rackpdu
from virtualpdu.pdu import pysnmp_handler

MISSING_CONFIG_MESSAGE = 'Missing configuration file as first parameter.\n'
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)


def main():
    try:
        config_file = sys.argv[1]
    except IndexError:
        sys.stderr.write(MISSING_CONFIG_MESSAGE)
        return 1
    else:
        config = configparser.RawConfigParser(
            {'debug_snmp': 'no',
             'snmp_versions': '1,2c',
             # SNMPv2c
             'community': None,
             # SNMPv3
             'engine_id': None,
             'context_engine_id': None,
             'context_name': '',
             'user': None,
             'auth_key': None,
             'auth_protocol': None,
             'priv_key': None,
             'priv_protocol': None}
        )

        config.read(config_file)
        driver = get_driver_from_config(config)
        mapping = get_mapping_for_config(config)
        outlet_default_state = get_default_state_from_config(config)

        debug_snmp = config.get('global', 'debug_snmp')

        core = virtualpdu.core.Core(driver=driver, mapping=mapping, store={},
                                    default_state=outlet_default_state)

        pdu_threads = []

        for pdu in [s for s in config.sections() if s != 'global']:
            apc_pdu = apc_rackpdu.APCRackPDU(pdu, core)

            listen_address = config.get(pdu, 'listen_address')
            listen_port = int(config.get(pdu, 'listen_port'))

            snmp_versions = config.get(pdu, 'snmp_versions')
            snmp_versions = [x.strip() for x in snmp_versions.split(',')]

            # SNMPv1/v2c options
            community = config.get(pdu, 'community')

            # SNMPv3 options
            engine_id = config.get(pdu, 'engine_id')
            if engine_id and engine_id.startswith('0x'):
                engine_id = engine_id[2:]
            context_engine_id = config.get(pdu, 'context_engine_id')
            if context_engine_id and context_engine_id.startswith('0x'):
                context_engine_id = context_engine_id[2:]
            context_name = config.get(pdu, 'context_name')
            user = config.get(pdu, 'user')
            auth_key = config.get(pdu, 'auth_key')
            auth_protocol = config.get(pdu, 'auth_protocol')
            priv_key = config.get(pdu, 'priv_key')
            priv_protocol = config.get(pdu, 'priv_protocol')

            snmp_harness = pysnmp_handler.SNMPPDUHarness(
                apc_pdu,
                listen_address,
                listen_port,
                snmp_versions=snmp_versions,
                community=community,
                engine_id=engine_id,
                context_engine_id=context_engine_id,
                context_name=context_name,
                user=user,
                auth_key=auth_key,
                auth_protocol=auth_protocol,
                priv_key=priv_key,
                priv_protocol=priv_protocol,
                debug_snmp=debug_snmp in ('yes', 'true', '1')
            )

            pdu_threads.append(snmp_harness)

        for t in pdu_threads:
            t.start()

        try:
            for t in pdu_threads:
                while t.is_alive():
                    t.join(1)

        except KeyboardInterrupt:
            for t in pdu_threads:
                t.stop()
            return 1

        return 0


def parse_default_state_config(default_state):
    supported_states = {
        'ON': virtualpdu.core.POWER_ON,
        'OFF': virtualpdu.core.POWER_OFF
    }
    try:
        return supported_states[default_state]
    except KeyError:
        invalid_outlet = "outlet_default_state must be " \
                         "one of {{{}}} but was {}"
        raise UnableToParseConfig(invalid_outlet.format(
                                  ", ".join(supported_states.keys()),
                                  default_state))


def get_driver_from_config(conf):
    try:
        uri = conf.get('global', 'libvirt_uri')
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        raise UnableToParseConfig(e)
    return libvirt_driver.LibvirtDriver(uri=uri)


def get_mapping_for_config(conf):
    sections = [s for s in conf.sections() if s != 'global']
    mapping = {}
    try:
        for pdu in sections:
            ports = conf.get(pdu, 'ports')
            list_of_ports = ports.split(',')
            for data in list_of_ports:
                port, host = data.split(':')
                mapping[(pdu, int(port))] = host
    except configparser.NoOptionError as e:
        raise UnableToParseConfig(e)
    return mapping


def get_default_state_from_config(conf):
    try:
        default_state = conf.get('global', 'outlet_default_state')
    except (configparser.NoSectionError, configparser.NoOptionError):
        default_state = 'ON'
    return parse_default_state_config(default_state)


class UnableToParseConfig(Exception):
    pass


if __name__ == '__main__':
    sys.exit(main())
