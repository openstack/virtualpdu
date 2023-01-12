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

from pyasn1.type import univ

from virtualpdu.pdu import baytech_mrp27
from virtualpdu.pdu import sysDescr
from virtualpdu.pdu import sysObjectID
from virtualpdu.tests import base
from virtualpdu.tests.unit.pdu.base_pdu_test_cases import BasePDUTests


class TestBaytechMRP27PDU(base.TestCase, BasePDUTests):
    pdu_class = baytech_mrp27.BaytechMRP27PDU
    outlet_control_class = baytech_mrp27.BaytechMRP27PDUOutletControl
    outlet_control_oid = \
        baytech_mrp27.sBTA_modules_RPC_outlet_state \
        + (1, baytech_mrp27.BaytechMRP27PDU.outlet_index_start,)

    def test_read_system_description(self):
        self.assertEqual(
            univ.OctetString("Universal RPC Host Module (virtualpdu)"),
            self.pdu.oid_mapping[sysDescr].value
        )

    def test_read_system_oid(self):
        self.assertEqual(
            univ.ObjectIdentifier(baytech_mrp27.sBTA),
            self.pdu.oid_mapping[sysObjectID].value
        )

    def test_as_many_outlets_as_specified_by_constructor(self):
        pdu = self.pdu_class(name='test_pdu',
                             core=self.core_mock,
                             outlet_count=10)
        self.assertEqual(10, pdu.outlet_count)
        self.assertEqual(10, len([oid for oid in pdu.oid_mapping.values()
                                  if type(oid) is self.outlet_control_class]))

    def test_as_many_outlets_as_specified_by_type(self):
        self.assertEqual(self.pdu_class.outlet_count, self.pdu.outlet_count)
        self.assertEqual(self.pdu_class.outlet_count,
                         len([oid for oid in self.pdu.oid_mapping.values()
                              if type(oid) is self.outlet_control_class]))
