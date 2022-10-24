import datetime
import os
import sys
import uuid

parent_folder = os.path.abspath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(parent_folder)

from common.policy_recommendation import generate_k8s_np, generate_anp, generate_reject_acnp

class Result:
    def __init__(self, job_type, recommendation_id, policy):
        self.job_type = job_type
        if not recommendation_id:
            self.recommendation_id = str(uuid.uuid4())
        else:
            self.recommendation_id = recommendation_id
        self.time_created = datetime.datetime.now()
        self.yamls = policy

class PolicyRecommendation:
    def __init__(self):
        self._ingresses = set()
        self._egresses = set()

    def process(self,
                jobType,
                recommendationId,
                isolationMethod,
                nsAllowList,
                toServices,
                appliedTo,
                ingress,
                egress):
        assert(jobType == "initial")
        # toServices is mandatory now. Because we need to create ClusterGroup
        # for Services if toServices is not enabled, which may be duplicate
        # among different partitions.
        assert(toServices == True)
        # ideally this would be done in the constructor, but this is not
        # supported in Snowflake (passing arguments once via the constructor)
        # instead we will keep overriding self._jobType with the same value
        self._jobType = jobType
        self._recommendationId = recommendationId
        self._isolationMethod = isolationMethod
        self._nsAllowList = nsAllowList
        self._toServices = toServices
        self._applied_to = appliedTo
        self._ingresses.add(ingress)
        self._egresses.add(egress)
        yield None

    def end_partition(self):
        nsAllowList = self._nsAllowList.split(',')
        if self._isolationMethod == 3:
            allow_policy = generate_k8s_np(self._applied_to, self._ingresses, self._egresses, nsAllowList)
            if allow_policy:
                result = Result(self._jobType,  self._recommendationId, allow_policy)
                yield(result.job_type, result.recommendation_id, result.time_created, result.yamls)
        else:
            allow_policy = generate_anp(self._applied_to, self._ingresses, self._egresses, nsAllowList)
            if allow_policy:
                result = Result(self._jobType,  self._recommendationId, allow_policy)
                yield(result.job_type, result.recommendation_id, result.time_created, result.yamls)
            if self._isolationMethod == 1:
                reject_policy = generate_reject_acnp(self._applied_to, nsAllowList)
                if reject_policy:
                    result = Result(self._jobType,  self._recommendationId, reject_policy)
                    yield(result.job_type, result.recommendation_id, result.time_created, result.yamls)
