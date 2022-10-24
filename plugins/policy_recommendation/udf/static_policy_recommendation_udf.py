import datetime
import os
import sys
import uuid

parent_folder = os.path.abspath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(parent_folder)

from common.policy_recommendation import recommend_policies_for_ns_allow_list, reject_all_acnp

class Result:
    def __init__(self, job_type, recommendation_id, policy):
        self.job_type = job_type
        if not recommendation_id:
            self.recommendation_id = str(uuid.uuid4())
        else:
            self.recommendation_id = recommendation_id
        self.time_created = datetime.datetime.now()
        self.yamls = policy

class StaticPolicyRecommendation:
    def __init__(self):
       return

    def process(self,
                jobType,
                recommendationId,
                isolationMethod,
                nsAllowList):
        self._jobType = jobType
        self._recommendationId = recommendationId
        self._nsAllowList = nsAllowList
        self._isolationMethod = isolationMethod
        yield None
    
    def end_partition(self):
        if self._nsAllowList:
            ns_allow_policies = recommend_policies_for_ns_allow_list(self._nsAllowList.split(','))
            for policy in ns_allow_policies:
                result = Result(self._jobType, self._recommendationId, policy)
                yield(result.job_type, result.recommendation_id, result.time_created, result.yamls)
        if self._isolationMethod == 2:
            reject_all_policy = reject_all_acnp()
            result = Result(self._jobType, self._recommendationId, reject_all_policy)
            yield(result.job_type, result.recommendation_id, result.time_created, result.yamls)
