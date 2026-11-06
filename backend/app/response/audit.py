
from datetime import datetime
from typing import Any


VALID_SEQUENCES = {
    "pending_approval": [
        ["response_request_created"],
    ],
    "approved": [
        ["response_request_created", "response_approved"],
    ],
    "rejected": [
        ["response_request_created"],
        ["response_request_created", "response_rejected"],
    ],
    "simulated": [
        [
            "response_request_created",
            "response_approved",
            "response_simulated",
        ],
    ],
}


def _parse_timestamp(value: Any):
    if not isinstance(value, str):
        return None

    try:
        timestamp = datetime.fromisoformat(value)
        if timestamp.tzinfo is None:
            return None
        return timestamp
    except ValueError:
        return None


def validate_response_audit(
    record: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate consistency between a response record and its audit log.

    This is a read-only consistency check. It does not provide
    cryptographic tamper protection or prevent database modification.
    """

    errors = []

    def error(message: str):
        errors.append(message)

    audit_log = record.get("audit_log")

    if not isinstance(audit_log, list):
        return {
            "valid": False,
            "errors": ["Audit log must be a list."],
        }

    if not audit_log:
        return {
            "valid": False,
            "errors": ["Response has no audit events."],
        }

    status = record.get("status")

    if status not in VALID_SEQUENCES:
        error(f"Unsupported response status: {status}")

    if any(not isinstance(event, dict) for event in audit_log):
        return {
            "valid": False,
            "errors": errors + [
                "Every audit event must be an object."
            ],
        }

    event_names = [
        event.get("event")
        for event in audit_log
    ]

    if (
        status in VALID_SEQUENCES
        and event_names not in VALID_SEQUENCES[status]
    ):
        error("Audit event sequence does not match response status.")

    previous_id = None
    previous_timestamp = None

    for index, event in enumerate(audit_log):
        if event.get("response_id") != record.get("id"):
            error(
                f"Audit event {index} references the wrong response."
            )

        if event.get("alert_id") != record.get("alert_id"):
            error(
                f"Audit event {index} references the wrong alert."
            )

        actor = event.get("actor")

        if not isinstance(actor, str) or not actor.strip():
            error(
                f"Audit event {index} has no valid actor."
            )

        if not isinstance(event.get("details"), dict):
            error(
                f"Audit event {index} has invalid details."
            )

        event_id = event.get("id")

        if type(event_id) is not int:
            error(
                f"Audit event {index} has an invalid ID."
            )
        elif previous_id is not None and event_id <= previous_id:
            error("Audit event IDs are not strictly increasing.")

        if type(event_id) is int:
            previous_id = event_id

        timestamp = _parse_timestamp(event.get("created_at"))

        if timestamp is None:
            error(
                f"Audit event {index} has an invalid timestamp."
            )
        elif (
            previous_timestamp is not None
            and timestamp < previous_timestamp
        ):
            error("Audit event timestamps are not chronological.")

        if timestamp is not None:
            previous_timestamp = timestamp

    if errors:
        return {
            "valid": False,
            "errors": errors,
        }

    creation = audit_log[0]
    creation_details = creation["details"]

    if creation["event"] != "response_request_created":
        error("First audit event must record request creation.")

    if creation["actor"] != record.get("requested_by"):
        error("Request creator does not match the response record.")

    for field in (
        "action",
        "target",
        "policy_allowed",
        "approval_required",
        "executed",
        "simulated",
    ):
        if creation_details.get(field) != record.get(field):
            error(
                f"Creation event {field} does not match the response record."
            )

    if record.get("action") != "block_ip":
        error("Unsupported response action.")

    if record.get("mode") != "dry_run":
        error("Response mode must be dry_run.")

    creation_timestamp = _parse_timestamp(creation.get("created_at"))
    response_timestamp = _parse_timestamp(record.get("created_at"))

    if (
        creation_timestamp is not None
        and response_timestamp is not None
        and creation_timestamp != response_timestamp
    ):
        error("Creation timestamp does not match the response record.")

    initial_status = creation_details.get("status")

    if initial_status not in {
        "pending_approval",
        "rejected",
    }:
        error("Created event contains an invalid initial status.")

    if initial_status == "pending_approval":
        if record.get("policy_allowed") is not True:
            error("Pending request must have an allowed policy.")

        if record.get("approval_required") is not True:
            error("Pending request must require approval.")

    elif initial_status == "rejected":
        if record.get("policy_allowed") is not False:
            error("Policy-rejected request must have a denied policy.")

    if record.get("executed") is not False:
        error("Response must not claim real execution.")

    if status != "simulated" and record.get("simulated") is not False:
        error("Non-simulated response cannot claim simulated=True.")

    if status == "pending_approval":
        if initial_status != "pending_approval":
            error("Pending response has an inconsistent initial status.")

        if record.get("decided_by") is not None:
            error("Pending response unexpectedly has a decision actor.")

        if record.get("decision_at") is not None:
            error("Pending response unexpectedly has a decision timestamp.")

        if record.get("decision_reason") is not None:
            error("Pending response unexpectedly has a decision reason.")

    elif status == "rejected" and len(audit_log) == 1:
        if initial_status != "rejected":
            error(
                "Policy-rejected response must have an initial rejected status."
            )

        if record.get("decided_by") is not None:
            error("Policy-rejected response cannot have an approver.")

        if record.get("decision_at") is not None:
            error("Policy-rejected response cannot have a decision timestamp.")

        if record.get("decision_reason") is not None:
            error("Policy-rejected response cannot have a decision reason.")

    elif status in {"approved", "rejected", "simulated"}:
        if initial_status != "pending_approval":
            error("Approver decision must follow a pending request.")

        decision = audit_log[1]
        decision_details = decision["details"]

        expected_event = (
            "response_approved"
            if status in {"approved", "simulated"}
            else "response_rejected"
        )

        if decision.get("event") != expected_event:
            error("Decision event name does not match the response status.")

        if decision.get("actor") != record.get("decided_by"):
            error("Decision actor does not match the response record.")

        if decision_details.get("decided_by") != record.get("decided_by"):
            error("Decision details contain an inconsistent approver.")

        if decision_details.get("previous_status") != "pending_approval":
            error("Decision event has an invalid previous status.")

        expected_status = "approved" if status == "simulated" else status

        if decision_details.get("new_status") != expected_status:
            error("Decision event does not match the response status.")

        if decision_details.get("decision_reason") != record.get(
            "decision_reason"
        ):
            error("Decision reason does not match the response record.")

        if decision_details.get("executed") is not False:
            error("Decision event cannot claim execution.")

        if decision_details.get("simulated") is not False:
            error("Decision event cannot claim simulation.")

        if record.get("decided_by") == record.get("requested_by"):
            error("Requester cannot approve or reject their own request.")

        decision_timestamp = _parse_timestamp(
            decision.get("created_at")
        )
        stored_decision_timestamp = _parse_timestamp(
            record.get("decision_at")
        )

        if (
            decision_timestamp is None
            or stored_decision_timestamp is None
            or decision_timestamp != stored_decision_timestamp
        ):
            error("Decision timestamp does not match the audit event.")

    if status == "simulated":
        simulation = audit_log[2]
        simulation_details = simulation["details"]

        if record.get("simulated") is not True:
            error("Simulated status requires simulated=True.")

        if record.get("executed") is not False:
            error("Dry-run simulation must not be executed.")

        if simulation.get("actor") != record.get("requested_by"):
            error("Simulation actor does not match the requesting analyst.")

        if simulation_details.get("simulation_mode") != "dry_run":
            error("Simulation mode must be dry_run.")

        if simulation_details.get("action") != record.get("action"):
            error("Simulation action does not match the response record.")

        if simulation_details.get("target") != record.get("target"):
            error("Simulation target does not match the response record.")

        if simulation_details.get("outcome") != "would_block":
            error("Simulation outcome is invalid.")

        for field in (
            "firewall_modified",
            "network_modified",
            "operating_system_command_executed",
            "executed",
        ):
            if simulation_details.get(field) is not False:
                error(
                    f"Simulation safety field {field} must be False."
                )

        if simulation_details.get("simulated") is not True:
            error("Simulation event must record simulated=True.")

    return {
        "valid": not errors,
        "errors": errors,
    }
