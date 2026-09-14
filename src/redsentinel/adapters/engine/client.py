from __future__ import annotations

from redsentinel.application.contracts import EvaluationRequest, EvaluationStatus


class EvaluationClient:
    def __init__(self, service) -> None:
        self.service = service

    def run_private_evaluation(self, request: EvaluationRequest) -> EvaluationStatus:
        return self.service.run_evaluation(request)
