
import ipaddress

from app.response.models import (
    PolicyDecision,
    ResponseAction,
    ResponseRequest,
)


class ResponsePolicyEngine:
    """
    Evaluates whether a response request satisfies AEGIS safety policy.

    This initial policy supports simulated public-IP containment only.
    It never executes an operating-system or firewall command.
    """

    def evaluate(
        self,
        request: ResponseRequest,
    ) -> PolicyDecision:
        reasons: list[str] = []

        if request.alert_id <= 0:
            reasons.append("A valid positive alert ID is required.")

        if request.action != ResponseAction.BLOCK_IP:
            reasons.append("The requested response action is unsupported.")
            return PolicyDecision(
                allowed=False,
                approval_required=True,
                reasons=tuple(reasons),
            )

        try:
            address = ipaddress.ip_address(request.target)
        except ValueError:
            reasons.append("The target must be a valid IP address.")
            return PolicyDecision(
                allowed=False,
                approval_required=True,
                reasons=tuple(reasons),
            )

        if not address.is_global:
            reasons.append(
                "Only globally routable IP addresses are eligible "
                "for this simulated response."
            )

        if not request.requested_by.strip():
            reasons.append("A response requester must be identified.")

        if reasons:
            return PolicyDecision(
                allowed=False,
                approval_required=True,
                reasons=tuple(reasons),
            )

        return PolicyDecision(
            allowed=True,
            approval_required=True,
            reasons=(
                "The request passed initial policy validation.",
                "Analyst approval is required before any real containment.",
                "Only dry-run execution is currently supported.",
            ),
        )

