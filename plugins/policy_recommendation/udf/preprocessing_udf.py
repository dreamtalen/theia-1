import os
import sys

parent_folder = os.path.abspath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(parent_folder)

from common.processing import parseLabels, get_flow_type, get_protocol_string

ROW_DELIMITER = "#"
    
class Result:
    def __init__(self, applied_to, ingress, egress):
        self.applied_to = applied_to
        self.ingress = ingress
        self.egress = egress

class PreProcessing:
    def __init__(self):
        return

    def process(self,
                jobType,
                isolationMethod,
                nsAllowList,
                labelIgnoreList,
                toServices,
                sourcePodNamespace,
                sourcePodLabels,
                destinationIP,
                destinationPodNamespace,
                destinationPodLabels,
                destinationServicePortName,
                destinationTransportPort,
                protocolIdentifier,
                flowType):
        labelsToIgnore = []
        if labelIgnoreList:
            labelsToIgnore = labelIgnoreList.split(',')
        sourcePodLabels = parseLabels(sourcePodLabels, labelsToIgnore)
        destinationPodLabels = parseLabels(destinationPodLabels, labelsToIgnore)
        flowType = get_flow_type(flowType, destinationServicePortName, destinationPodLabels)
        protocolIdentifier = get_protocol_string(protocolIdentifier)
        
        # Build row for source Pod as applied_to
        applied_to = ROW_DELIMITER.join([sourcePodNamespace, sourcePodLabels])
        if flowType == "pod_to_external":
            egress = ROW_DELIMITER.join([destinationIP, str(destinationTransportPort), protocolIdentifier])
        elif flowType == "pod_to_svc" and isolationMethod != 3:
            # K8s policies don't support Pod to Service rules
            svc_ns, svc_name = destinationServicePortName.partition(':')[0].split('/')
            egress = ROW_DELIMITER.join([svc_ns, svc_name])
        else:
            egress = ROW_DELIMITER.join([destinationPodNamespace, destinationPodLabels, str(destinationTransportPort), protocolIdentifier])
        row = Result(applied_to, "", egress)
        yield(row.applied_to, row.ingress, row.egress)

        # Build row for destination Pod (if possible) as applied_to
        if flowType != "pod_to_external":
            applied_to = ROW_DELIMITER.join([destinationPodNamespace, destinationPodLabels])
            ingress = ROW_DELIMITER.join([sourcePodNamespace, sourcePodLabels, str(destinationTransportPort), protocolIdentifier])
            row = Result(applied_to, ingress, "")
            yield(row.applied_to, row.ingress, row.egress)
