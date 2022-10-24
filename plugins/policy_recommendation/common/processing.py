#!/usr/bin/python3

# Copyright 2022 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

def parseLabels(labels, omitKeys = []):
    if not labels:
        return "{}"
    # Just for PoC, generated records having labels in single-quote
    labels = labels.replace("\'", "\"")
    labels_dict = json.loads(labels)
    labels_dict = {
        key: value
        for key, value in labels_dict.items()
        if key not in omitKeys
    }
    return json.dumps(labels_dict, sort_keys=True)

def get_flow_type(flowType, destinationServicePortName, destinationPodLabels):
    if flowType == 3:
        return "pod_to_external"
    elif destinationServicePortName:
        return "pod_to_svc"
    elif destinationPodLabels:
        return "pod_to_pod"
    else:
        return "pod_to_external"

def get_protocol_string(protocolIdentifier):
    if protocolIdentifier == 6:
        return "TCP"
    elif protocolIdentifier == 17:
        return "UDP"
    else:
        return "UNKNOWN"
