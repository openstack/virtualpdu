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

from mock import Mock
from mock import patch
from mock import sentinel

from pysnmp.proto.rfc1902 import Integer
from pysnmp.proto.rfc1902 import ObjectName
from pysnmp.proto.rfc1902 import ObjectSyntax
from pysnmp.proto.rfc1902 import OctetString
from pysnmp.proto.rfc1902 import SimpleSyntax

from pysnmp.proto.rfc1905 import _BindValue
from pysnmp.proto.rfc1905 import NoSuchInstance
from pysnmp.proto.rfc1905 import PDUs
from pysnmp.proto.rfc1905 import ResponsePDU
from pysnmp.proto.rfc1905 import VarBindList

from virtualpdu.pdu.pysnmp_handler import SNMPPDUHandler
from virtualpdu.tests.unit import TraversableMessage

SNMP_ERR_noSuchName = 2
SNMP_ERR_genErr = 5

# snmpget -v2c -c community localhost:10610 .1.1
MSG_SNMP_GET = (b'0%\x02\x01\x01\x04\tcommunity\xa0\x15\x02\x04$=W\xfd\x02\x01'
                b'\x00\x02\x01\x000\x070\x05\x06\x01)\x05\x00')

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
        self.pdu_mock = Mock()
        self.pdu_mock.oid_mapping = {}
        self.transport_dispatcher = Mock()
        self.pdu_handler = SNMPPDUHandler(self.pdu_mock, 'community')
        self.encoder_patcher = patch('virtualpdu.pdu.pysnmp_handler.encoder')
        self.encoder_mock = self.encoder_patcher.start()
        self.encoder_mock.return_value = sentinel.encoded_message

    def tearDown(self):
        self.encoder_patcher.stop()

    def test_set_calls_pdu_mock(self):
        self.pdu_mock.oid_mapping[(1, 1)] = Mock()

        self.pdu_handler.message_handler(self.transport_dispatcher,
                                         sentinel.transport_domain,
                                         sentinel.transport_address,
                                         MSG_SNMP_SET)
        self.assertEqual(self.pdu_mock.oid_mapping[(1, 1)].value, 5)

    def test_set_response(self):
        self.pdu_mock.oid_mapping[(1, 1)] = Mock()

        self.pdu_handler.message_handler(self.transport_dispatcher,
                                         sentinel.transport_domain,
                                         sentinel.transport_address,
                                         MSG_SNMP_SET)

        message = TraversableMessage(self.encoder_mock.encode.call_args[0][0])
        varbindlist = message[PDUs][ResponsePDU][VarBindList]

        self.assertEqual(varbindlist[0][ObjectName].value, (1, 1))
        self.assertEqual(varbindlist[0][_BindValue][ObjectSyntax]
                         [SimpleSyntax][Integer].value,
                         Integer(5))

    def test_set_with_unknown_oid_replies_nosuchinstance(self):
        self.pdu_handler.message_handler(self.transport_dispatcher,
                                         sentinel.transport_domain,
                                         sentinel.transport_address,
                                         MSG_SNMP_SET)

        message = TraversableMessage(self.encoder_mock.encode.call_args[0][0])
        varbindlist = message[PDUs][ResponsePDU][VarBindList]
        self.assertEqual(varbindlist[0][ObjectName].value, (1, 1))
        self.assertEqual(varbindlist[0][NoSuchInstance].value,
                         NoSuchInstance())

    def test_get(self):
        self.pdu_mock.oid_mapping[(1, 1)] = Mock()
        self.pdu_mock.oid_mapping[(1, 1)].value = OctetString('test')

        self.pdu_handler.message_handler(self.transport_dispatcher,
                                         sentinel.transport_domain,
                                         sentinel.transport_address,
                                         MSG_SNMP_GET)

        message = TraversableMessage(self.encoder_mock.encode.call_args[0][0])
        varbindlist = message[PDUs][ResponsePDU][VarBindList]

        self.assertEqual(varbindlist[0][ObjectName].value, (1, 1))
        self.assertEqual(varbindlist[0][_BindValue][ObjectSyntax]
                         [SimpleSyntax][OctetString].value,
                         OctetString("test"))

    def test_get_next(self):
        self.pdu_mock.oid_mapping[(1, 1)] = Mock()
        self.pdu_mock.oid_mapping[(1, 2)] = Mock()
        self.pdu_mock.oid_mapping[(1, 2)].value = Integer(5)

        self.pdu_handler.message_handler(self.transport_dispatcher,
                                         sentinel.transport_domain,
                                         sentinel.transport_address,
                                         MSG_SNMP_WALK)

        message = TraversableMessage(self.encoder_mock.encode.call_args[0][0])
        varbindlist = message[PDUs][ResponsePDU][VarBindList]
        self.assertEqual(varbindlist[0][ObjectName].value, (1, 2))
        self.assertEqual(varbindlist[0][_BindValue][ObjectSyntax]
                         [SimpleSyntax][Integer].value,
                         Integer(5))

    def test_unsupported_command_returns_genError(self):
        self.pdu_handler.message_handler(self.transport_dispatcher,
                                         sentinel.transport_domain,
                                         sentinel.transport_address,
                                         MSG_SNMP_BULK_GET)

        message = TraversableMessage(self.encoder_mock.encode.call_args[0][0])

        self.assertEqual(message[PDUs][ResponsePDU].get_by_index(1).value,
                         Integer(SNMP_ERR_genErr))

    def test_doesnt_reply_with_wrong_community(self):
        self.pdu_handler.message_handler(self.transport_dispatcher,
                                         sentinel.transport_domain,
                                         sentinel.transport_address,
                                         MSG_SNMP_WRONG_COMM)

        self.assertFalse(self.transport_dispatcher.sendMessage.called)
