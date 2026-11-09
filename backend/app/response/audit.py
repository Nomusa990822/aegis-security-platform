
from datetime import datetime
from typing import Any


LEGACY_CREATION_EVENT = "response_preview_created"

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
        [LEGACY_CREATION_EVENT],
    ],
    "simulated": [
        [
            "response_request_created",
            "response_approved",
            "response_simulated",
        ],
    ],
}


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None

    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        parsed = datetime.fromisoformat(value)

        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None

        return parsed
    except (TypeError, ValueError):
        return None


def validate_response_audit(
    record: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate consistency between a response record and its audit log.

    This is a read-only consistency check. It does not provide
    cryptographic tamper protection or prevent database modification.
    """
    errors: list[str] = []

    def err(message: str) -> None:
        errors.append(message)

    if not isinstance(record, dict):
        return {
            "valid": False,
            "errors": ["Response record must be an object."],
        }

    reasons = record.get("reasons")
    if not isinstance(reasons, list) or any(
        not isinstance(reason, str)
        for reason in reasons
    ):
        err("Response reasons must be a list of strings.")

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

    if any(not isinstance(event, dict) for event in audit_log):
        return {
            "valid": False,
            "errors": ["Every audit event must be an object."],
        }

    status = record.get("status")

    if status not in VALID_SEQUENCES:
        err(f"Unsupported response status: {status}")
        return {"valid": False, "errors": errors}

    event_names = [event.get("event") for event in audit_log]

    if event_names not in VALID_SEQUENCES[status]:
        err("Audit event sequence does not match response status.")

    previous_id = None
    previous_timestamp = None

    for index, event in enumerate(audit_log):
        if event.get("response_id") != record.get("id"):
            err(f"Audit event {index} references the wrong response.")

        if event.get("alert_id") != record.get("alert_id"):
            err(f"Audit event {index} references the wrong alert.")

        if not isinstance(event.get("event"), str) or not event["event"]:
            err(f"Audit event {index} has no valid event name.")

        if not isinstance(event.get("actor"), str) or not event["actor"].strip():
            err(f"Audit event {index} has no valid actor.")

        if not isinstance(event.get("details"), dict):
            err(f"Audit event {index} has invalid details.")
            continue

        event_id = event.get("id")

        if type(event_id) is not int:
            err(f"Audit event {index} has an invalid ID.")
        elif previous_id is not None and event_id <= previous_id:
            err(f"Audit event {index} IDs are not strictly increasing.")

        if type(event_id) is int:
            previous_id = event_id

        timestamp = parse_timestamp(event.get("created_at"))

        if timestamp is None:
            err(f"Audit event {index} has an invalid timestamp.")
        elif previous_timestamp is not None and timestamp < previous_timestamp:
            err(f"Audit event {index} timestamps are not chronological.")

        if timestamp is not None:
            previous_timestamp = timestamp

    if errors:
        return {"valid": False, "errors": errors}

    creation = audit_log[0]
    creation_details = creation["details"]
    legacy_creation = creation.get("event") == LEGACY_CREATION_EVENT

    if legacy_creation:
        if status != "rejected" or len(audit_log) != 1:
            err(
                "Legacy preview event is only valid for a "
                "single-event policy rejection."
            )

        if creation.get("actor") != record.get("requested_by"):
            err("Request creator does not match the response record.")

        # The historical event recorded only these five fields.
        # Do not require fields that did not exist in that schema.
        for field in (
            "status",
            "action",
            "target",
            "executed",
            "simulated",
        ):
            if creation_details.get(field) != record.get(field):
                err(
                    f"Legacy creation event {field} does not match "
                    "the response record."
                )

        if record.get("policy_allowed") is not False:
            err("Legacy policy-rejected response must have a denied policy.")

        if record.get("executed") is not False:
            err("Legacy policy-rejected response cannot claim execution.")

        if record.get("simulated") is not False:
            err("Legacy policy-rejected response cannot claim simulation.")

    else:
        if creation.get("event") != "response_request_created":
            err("First audit event must record request creation.")

        if creation.get("actor") != record.get("requested_by"):
            err("Request creator does not match the response record.")

        for field in (
            "action",
            "target",
            "policy_allowed",
            "approval_required",
            "executed",
        ):
            if creation_details.get(field) != record.get(field):
                err(
                    f"Creation event {field} does not match the response record."
                )

        # New creation events bind the original policy reasons into the
        # signed audit chain. Missing reasons remain accepted for historical
        # events created before this field was added to the event schema.
        if "reasons" in creation_details:
            if creation_details.get("reasons") != record.get("reasons"):
                err("Creation event reasons do not match the response record.")

        # Bind the execution mode to the original request when present.
        # Historical creation events without this field remain compatible.
        if "mode" in creation_details:
            if creation_details.get("mode") != record.get("mode"):
                err("Creation event mode does not match the response record.")

        # The creation event records the original request state.
        # Simulation happens later and must not alter this event.
        if creation_details.get("simulated") is not False:
            err("Creation event cannot claim that a response was simulated.")

    if record.get("action") != "block_ip":
        err("Unsupported response action.")

    if record.get("mode") != "dry_run":
        err("Response mode must be dry_run.")

    if record.get("executed") is not False:
        err("Response must not claim real execution.")

    if status != "simulated" and record.get("simulated") is not False:
        err("Non-simulated response cannot claim simulated=True.")

    creation_timestamp = parse_timestamp(creation.get("created_at"))
    response_timestamp = parse_timestamp(record.get("created_at"))

    if (
        creation_timestamp is None
        or response_timestamp is None
        or creation_timestamp != response_timestamp
    ):
        err("Creation timestamp does not match the response record.")

    initial_status = creation_details.get("status")

    if initial_status not in {"pending_approval", "rejected"}:
        err("Created event contains an invalid initial status.")

    if legacy_creation and initial_status != "rejected":
        err("Legacy preview event must record a rejected initial status.")

    if initial_status == "pending_approval":
        if record.get("policy_allowed") is not True:
            err("Pending request must have an allowed policy.")

        if record.get("approval_required") is not True:
            err("Pending request must require approval.")

    elif initial_status == "rejected":
        if record.get("policy_allowed") is not False:
            err("Policy-rejected request must have a denied policy.")

    if status == "pending_approval":
        if initial_status != "pending_approval":
            err("Pending response has an inconsistent initial status.")

        if record.get("decided_by") is not None:
            err("Pending response unexpectedly has a decision actor.")

        if record.get("decision_at") is not None:
            err("Pending response unexpectedly has a decision timestamp.")

        if record.get("decision_reason") is not None:
            err("Pending response unexpectedly has a decision reason.")

    elif status == "rejected" and len(audit_log) == 1:
        # Policy rejection occurs during request evaluation.
        if initial_status != "rejected":
            err("Policy-rejected response must have an initial rejected status.")

        if record.get("decided_by") is not None:
            err("Policy-rejected response cannot have an approver.")

        if record.get("decision_at") is not None:
            err("Policy-rejected response cannot have a decision timestamp.")

        if record.get("decision_reason") is not None:
            err("Policy-rejected response cannot have a decision reason.")

    elif status in {"approved", "rejected", "simulated"}:
        # An approver decision must follow a pending request.
        if initial_status != "pending_approval":
            err("Approver decision must follow a pending request.")

        decision = audit_log[1]
        decision_details = decision["details"]

        expected_event = (
            "response_approved"
            if status in {"approved", "simulated"}
            else "response_rejected"
        )

        if decision.get("event") != expected_event:
            err("Decision event name does not match the response status.")

        if decision.get("actor") != record.get("decided_by"):
            err("Decision actor does not match the response record.")

        if decision_details.get("decided_by") != record.get("decided_by"):
            err("Decision details contain an inconsistent approver.")

        if decision_details.get("previous_status") != "pending_approval":
            err("Decision event has an invalid previous status.")

        expected_status = "approved" if status == "simulated" else status

        if decision_details.get("new_status") != expected_status:
            err("Decision event does not match the response status.")

        if decision_details.get("decision_reason") != record.get(
            "decision_reason"
        ):
            err("Decision reason does not match the response record.")

        if decision_details.get("executed") is not False:
            err("Decision event cannot claim execution.")

        if decision_details.get("simulated") is not False:
            err("Decision event cannot claim simulation.")

        if record.get("requested_by") == record.get("decided_by"):
            err("Requester cannot approve or reject their own request.")

        decision_timestamp = parse_timestamp(decision.get("created_at"))
        stored_decision_timestamp = parse_timestamp(record.get("decision_at"))

        if (
            decision_timestamp is None
            or stored_decision_timestamp is None
            or decision_timestamp != stored_decision_timestamp
        ):
            err("Decision timestamp does not match the audit event.")

    if status == "simulated":
        simulation = audit_log[2]
        simulation_details = simulation["details"]

        # The simulation actor may differ from the original requester.
        # New events duplicate that identity in details so consistency
        # validation can detect an actor field changed independently.
        # Missing simulated_by is accepted for historical event compatibility.
        if "simulated_by" in simulation_details:
            simulated_by = simulation_details.get("simulated_by")
            if (
                not isinstance(simulated_by, str)
                or not simulated_by.strip()
                or simulation.get("actor") != simulated_by
            ):
                err("Simulation actor does not match the recorded simulator.")

        expected_simulation_values = {
            "simulation_mode": "dry_run",
            "action": record.get("action"),
            "target": record.get("target"),
            "outcome": "would_block",
            "firewall_modified": False,
            "network_modified": False,
            "operating_system_command_executed": False,
            "executed": False,
            "simulated": True,
        }

        for field, expected in expected_simulation_values.items():
            if simulation_details.get(field) != expected:
                err(
                    f"Simulation event {field} does not match "
                    "the expected safe dry-run value."
                )

    return {
        "valid": not errors,
        "errors": errors,
    }
