
from app.response.models import (
    ExecutionMode,
    ResponseRequest,
    ResponseResult,
    ResponseStatus,
)
from app.response.policy import ResponsePolicyEngine


class ResponseEngine:
    """
    Coordinates policy evaluation and safe response simulation.

    Real response execution is intentionally disabled.
    """

    def __init__(
        self,
        policy_engine: ResponsePolicyEngine | None = None,
    ):
        self.policy_engine = (
            policy_engine or ResponsePolicyEngine()
        )

    def execute(
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
                    "Only dry-run execution is supported.",
                ),
            )

        return ResponseResult(
            status=ResponseStatus.SIMULATED,
            action=request.action.value,
            target=request.target,
            mode=request.mode.value,
            policy_allowed=True,
            approval_required=True,
            executed=False,
            simulated=True,
            reasons=decision.reasons + (
                "Simulation completed. No firewall or network changes were made.",
            ),
        )

