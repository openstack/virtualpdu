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


class SNMPErrorIndication(Exception):
    pass


class SNMPMessageProcessingError(SNMPErrorIndication):
    pass


class SerializationError(SNMPMessageProcessingError):
    pass


class DeserializationError(SNMPMessageProcessingError):
    pass


class ParseError(DeserializationError):
    pass


class UnsupportedMsgProcessingModel(SNMPMessageProcessingError):
    pass


class UnknownPDUHandler(SNMPMessageProcessingError):
    pass


class UnsupportedPDUtype(SNMPMessageProcessingError):
    pass


class RequestTimedOut(SNMPMessageProcessingError):
    pass


class EmptyResponse(SNMPMessageProcessingError):
    pass


class NonReportable(SNMPMessageProcessingError):
    pass


class DataMismatch(SNMPMessageProcessingError):
    pass


class EngineIDMismatch(SNMPMessageProcessingError):
    pass


class UnknownEngineID(SNMPMessageProcessingError):
    pass


class TooBig(SNMPMessageProcessingError):
    pass


class LoopTerminated(SNMPMessageProcessingError):
    pass


class InvalidMsg(SNMPMessageProcessingError):
    pass


class SNMPSecurityModuleError(SNMPErrorIndication):
    pass


class UnknownCommunityName(SNMPSecurityModuleError):
    pass


class NoEncryption(SNMPSecurityModuleError):
    pass


class EncryptionError(SNMPSecurityModuleError):
    pass


class DecryptionError(SNMPSecurityModuleError):
    pass


class NoAuthentication(SNMPSecurityModuleError):
    pass


class AuthenticationError(SNMPSecurityModuleError):
    pass


class AuthenticationFailure(SNMPSecurityModuleError):
    pass


class UnsupportedAuthProtocol(SNMPSecurityModuleError):
    pass


class UnsupportedPrivProtocol(SNMPSecurityModuleError):
    pass


class UnknownSecurityName(SNMPSecurityModuleError):
    pass


class UnsupportedSecurityModel(SNMPSecurityModuleError):
    pass


class UnsupportedSecurityLevel(SNMPSecurityModuleError):
    pass


class NotInTimeWindow(SNMPSecurityModuleError):
    pass


class SNMPAccessControlError(SNMPErrorIndication):
    pass


class NoSuchView(SNMPAccessControlError):
    pass


class NoAccessEntry(SNMPAccessControlError):
    pass


class NoGroupName(SNMPAccessControlError):
    pass


class NoSuchContext(SNMPAccessControlError):
    pass


class NotInView(SNMPAccessControlError):
    pass


class AccessAllowed(SNMPAccessControlError):
    pass


class OtherError(SNMPAccessControlError):
    pass


class SNMPApplicationError(SNMPErrorIndication):
    pass


class OidNotIncreasing(SNMPApplicationError):
    pass


class ReportPduReceived(SNMPErrorIndication):
    pass


class UnknownUserName(SNMPErrorIndication):
    pass


class WrongDigest(SNMPErrorIndication):
    pass
