
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class ResponseAction(str, Enum):
    BLOCK_IP = "block_ip"


class ExecutionMode(str, Enum):
    DRY_RUN = "dry_run"


class ResponseStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    SIMULATED = "simulated"


@dataclass(frozen=True)
class ResponseRequest:
    alert_id: int
    action: ResponseAction
    target: str
    mode: ExecutionMode = ExecutionMode.DRY_RUN
    requested_by: str = "system"


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    approval_required: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class ResponseResult:
    status: ResponseStatus
    action: str
    target: str
    mode: str
    policy_allowed: bool
    approval_required: bool
    executed: bool
    simulated: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        result["action"] = self.action
        result["mode"] = self.mode
        result["reasons"] = list(self.reasons)
        return result
