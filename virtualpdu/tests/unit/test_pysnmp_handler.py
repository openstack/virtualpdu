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

import unittest
# note(rpittau): related to F811, see tox.ini
# from unittest import mock
from unittest.mock import Mock
from unittest.mock import patch

from pysnmp.proto.errind import UnknownPDUHandler
from pysnmp.proto.rfc1902 import Integer
from pysnmp.proto.rfc1902 import ObjectName
from pysnmp.proto.rfc1902 import ObjectSyntax
from pysnmp.proto.rfc1902 import OctetString
from pysnmp.proto.rfc1902 import SimpleSyntax
from pysnmp.proto.rfc1905 import _BindValue
from pysnmp.proto.rfc1905 import NoSuchInstance
from pysnmp.proto.rfc1905 import VarBindList

from virtualpdu.pdu.pysnmp_handler import create_snmp_engine
from virtualpdu.tests.unit import TraversableMessage

# snmpget -v2c -c community localhost:10610 .1.1
MSG_SNMP_GET = (b'0%\x02\x01\x01\x04\tcommunity\xa0\x15\x02\x04$=W\xfd\x02\x01'
                b'\x00\x02\x01\x000\x070\x05\x06\x01)\x05\x00')

# snmpget -v2c -c community localhost:10610 .1.0
MSG_SNMP_GET_UNKNOWN_OID = (b'0%\x02\x01\x01\x04\tcommunity\xa0\x15\x02\x04'
                            b'$=W\xfd\x02\x01\x00\x02\x01\x000\x070\x05\x06'
                            b'\x01(\x05\x00')

# snmpset -v2c -c community localhost:10610 .1.1 i 5
MSG_SNMP_SET = (b'0&\x02\x01\x01\x04\tcommunity\xa3\x16\x02\x04ce\xd84\x02\x01'
                b'\x00\x02\x01'
                b'\x000\x080\x06\x06\x01)\x02\x01\x05')

# snmpwalk -v2c -c community localhost:10610 .1.1
MSG_SNMP_WALK = (b'0%\x02\x01\x01\x04\tcommunity\xa1\x15\x02\x04!\xe521\x02'
                 b'\x01\x00\x02\x01\x000\x070\x05\x06\x01)\x05\x00')

# snmpbulkget -v2c -c community localhost:10610 1.1 1.2
MSG_SNMP_BULK_GET = (b'0,\x02\x01\x01\x04\tcommunity\xa5\x1c\x02\x04\'\x0c'
                     b'\xcfj\x02\x01\x00\x02\x01\n0\x0e0\x05\x06\x01)\x05\x000'
                     b'\x05\x06\x01*\x05\x00')

# snmpget -v2c -c wrong_community localhost:10610 .1.1
MSG_SNMP_WRONG_COMM = (b'0+\x02\x01\x01\x04\x0fwrong_community\xa0\x15\x02'
                       b'\x04d\xab\xdb\xcc\x02\x01\x00\x02\x01\x000\x070\x05'
                       b'\x06\x01)\x05\x00')


class SnmpServiceMessageReceivedTest(unittest.TestCase):
    def setUp(self):
        self.power_unit_mock = Mock()
        self.power_unit_mock.oid_mapping = {}

        for pysnmp_package in ('asyncore', 'asynsock'):
            try:
                self.socket_patcher = patch('pysnmp.carrier.%s.dgram'
                                            '.base.DgramSocketTransport'
                                            '.openServerMode' % pysnmp_package)
                self.socket_patcher.start()

                break

            except ImportError:
                continue

        else:
            raise ImportError('Monkeys failed at pysnmp patching!')

        self.snmp_engine = create_snmp_engine(self.power_unit_mock,
                                              '127.0.0.1', 161,
                                              snmp_versions=['1', '2c'],
                                              community='community')

    def tearDown(self):
        self.snmp_engine.transportDispatcher.closeDispatcher()
        self.socket_patcher.stop()

    def test_set_calls_pdu_mock(self):
        self.power_unit_mock.oid_mapping[(1, 1)] = Mock()

        self.snmp_engine.msgAndPduDsp.receiveMessage(
            self.snmp_engine, (1, 3, 6, 1), ('127.0.0.1', 12345),
            MSG_SNMP_SET
        )

        self.assertEqual(self.power_unit_mock.oid_mapping[(1, 1)].value, 5)

    def test_set_response(self):
        self.power_unit_mock.oid_mapping[(1, 1)] = Mock()

        patcher = patch('virtualpdu.pdu.pysnmp_handler'
                        '.SetCommandResponder.handleMgmtOperation')
        mock = patcher.start()

        self.snmp_engine.msgAndPduDsp.receiveMessage(
            self.snmp_engine, (1, 3, 6, 1), ('127.0.0.1', 12345),
            MSG_SNMP_SET
        )

        message = TraversableMessage(mock.call_args[0][3])

        patcher.stop()

        varbindlist = message[VarBindList]

        self.assertEqual(varbindlist[0][ObjectName].value, (1, 1))
        self.assertEqual(varbindlist[0][_BindValue][ObjectSyntax]
                         [SimpleSyntax][Integer].value,
                         Integer(5))

    def test_get_with_unknown_oid_replies_nosuchinstance(self):

        patcher = patch('virtualpdu.pdu.pysnmp_handler'
                        '.GetCommandResponder.sendRsp')
        mock = patcher.start()

        self.snmp_engine.msgAndPduDsp.receiveMessage(
            self.snmp_engine, (1, 3, 6, 1), ('127.0.0.1', 12345),
            MSG_SNMP_GET_UNKNOWN_OID
        )

        varbindlist = mock.call_args[0][4]

        patcher.stop()

        self.assertEqual(varbindlist[0][0], (1, 0))
        self.assertIsInstance(varbindlist[0][1], NoSuchInstance)

    def test_get(self):
        self.power_unit_mock.oid_mapping[(1, 1)] = Mock()
        self.power_unit_mock.oid_mapping[(1, 1)].value = OctetString('test')

        patcher = patch('virtualpdu.pdu.pysnmp_handler'
                        '.GetCommandResponder.sendRsp')
        mock = patcher.start()

        self.snmp_engine.msgAndPduDsp.receiveMessage(
            self.snmp_engine, (1, 3, 6, 1), ('127.0.0.1', 12345),
            MSG_SNMP_GET
        )

        varbindlist = mock.call_args[0][4]

        patcher.stop()

        self.assertEqual(varbindlist[0][0], (1, 1))
        self.assertEqual(varbindlist[0][1], OctetString("test"))

    def test_get_next(self):
        self.power_unit_mock.oid_mapping[(1, 1)] = Mock()
        self.power_unit_mock.oid_mapping[(1, 2)] = Mock()
        self.power_unit_mock.oid_mapping[(1, 2)].value = Integer(5)

        patcher = patch('virtualpdu.pdu.pysnmp_handler'
                        '.NextCommandResponder.sendRsp')
        mock = patcher.start()

        self.snmp_engine.msgAndPduDsp.receiveMessage(
            self.snmp_engine, (1, 3, 6, 1), ('127.0.0.1', 12345),
            MSG_SNMP_WALK
        )

        varbindlist = mock.call_args[0][4]

        patcher.stop()

        self.assertEqual(varbindlist[0][0], (1, 2))
        self.assertEqual(varbindlist[0][1], Integer(5))

    def test_unsupported_command_returns_error(self):
        patcher = patch('pysnmp.proto.mpmod.rfc2576'
                        '.SnmpV2cMessageProcessingModel'
                        '.prepareResponseMessage')
        mock = patcher.start()
        mock.return_value = (
            (1, 3, 6, 1), ('127.0.0.1', 12345), b''
        )

        self.snmp_engine.msgAndPduDsp.receiveMessage(
            self.snmp_engine, (1, 3, 6, 1), ('127.0.0.1', 12345),
            MSG_SNMP_BULK_GET
        )

        status_info = mock.call_args[0][11]
        self.assertIsInstance(status_info['errorIndication'],
                              UnknownPDUHandler)

        patcher.stop()

    def test_doesnt_reply_with_wrong_community(self):
        patcher = patch('pysnmp.proto.mpmod.rfc2576'
                        '.SnmpV2cMessageProcessingModel'
                        '.prepareResponseMessage')
        mock = patcher.start()
        mock.return_value = (
            (1, 3, 6, 1), ('127.0.0.1', 12345), b''
        )

        self.snmp_engine.msgAndPduDsp.receiveMessage(
            self.snmp_engine, (1, 3, 6, 1), ('127.0.0.1', 12345),
            MSG_SNMP_WRONG_COMM
        )

        self.assertEqual(mock.call_count, 0)

        patcher.stop()
