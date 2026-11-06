
from app.response.models import (
    ExecutionMode,
    ResponseRequest,
    ResponseResult,
    ResponseStatus,
)
from app.response.policy import ResponsePolicyEngine


class ResponseEngine:
    """
    Evaluates response requests and places valid requests
    into the approval queue.

    This stage does not simulate or execute responses.
    """

    def __init__(
        self,
        policy_engine: ResponsePolicyEngine | None = None,
    ):
        self.policy_engine = (
            policy_engine or ResponsePolicyEngine()
        )

    def request_approval(
        self,
        request: ResponseRequest,
    ) -> ResponseResult:
        decision = self.policy_engine.evaluate(request)

        if not decision.allowed:
            return ResponseResult(
                status=ResponseStatus.REJECTED,
                action=request.action.value,
                target=request.target,
                mode=request.mode.value,
                policy_allowed=False,
                approval_required=decision.approval_required,
                executed=False,
                simulated=False,
                reasons=decision.reasons,
            )

        if request.mode != ExecutionMode.DRY_RUN:
            return ResponseResult(
                status=ResponseStatus.REJECTED,
                action=request.action.value,
                target=request.target,
                mode=request.mode.value,
                policy_allowed=True,
                approval_required=True,
                executed=False,
                simulated=False,
                reasons=(
                    "Only dry-run mode is supported.",
                ),
            )

        return ResponseResult(
            status=ResponseStatus.PENDING_APPROVAL,
            action=request.action.value,
            target=request.target,
            mode=request.mode.value,
            policy_allowed=True,
            approval_required=True,
            executed=False,
            simulated=False,
            reasons=decision.reasons + (
                "Response request recorded.",
                "A separate authorised approver must approve "
                "this request before simulation.",
                "No firewall or network changes were made.",
            ),
        )
