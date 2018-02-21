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


class TraversableMessage(object):
    def __init__(self, other):
        self.value = other

    def __getitem__(self, type_class):
        ret = None
        try:
            # this is required for ancient pyasn1 to work
            for idx in range(len(self.value)):
                component = self.value.getComponentByPosition(idx)
                if isinstance(component, type_class):
                    if ret:
                        raise KeyError()
                    ret = component
        except (TypeError, AttributeError):
            index = type_class
            ret = self.value[index]
        return TraversableMessage(ret)

    def get_by_index(self, index):
        return TraversableMessage(self.value[index])
