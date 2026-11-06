
from typing import Any


EXPECTED_EVENTS = {
    "pending_approval": [
        "response_request_created",
    ],
    "approved": [
        "response_request_created",
        "response_approved",
    ],
    "rejected": [
        "response_request_created",
        "response_rejected",
    ],
    "simulated": [
        "response_request_created",
        "response_approved",
        "response_simulated",
    ],
}


def validate_response_audit(
    record: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate consistency between a response record and its audit log.

    This is a read-only consistency check. It does not provide
    cryptographic tamper protection or prevent database modification.
    """

    errors = []
    audit_log = record.get("audit_log")

    if not isinstance(audit_log, list):
        return {
            "valid": False,
            "errors": ["Audit log must be a list."],
        }

    response_id = record.get("id")
    alert_id = record.get("alert_id")
    status = record.get("status")

    expected_events = EXPECTED_EVENTS.get(status)

    if expected_events is None:
        errors.append(f"Unsupported response status: {status}")
    elif [
        event.get("event")
        for event in audit_log
    ] != expected_events:
        errors.append(
            "Audit event sequence does not match response status."
        )

    if not audit_log:
        errors.append("Response has no audit events.")
        return {
            "valid": False,
            "errors": errors,
        }

    previous_id = None

    for index, event in enumerate(audit_log):
        if event.get("response_id") != response_id:
            errors.append(
                f"Audit event {index} references the wrong response."
            )

        if event.get("alert_id") != alert_id:
            errors.append(
                f"Audit event {index} references the wrong alert."
            )

        if not event.get("actor"):
            errors.append(
                f"Audit event {index} has no actor."
            )

        if not isinstance(event.get("details"), dict):
            errors.append(
                f"Audit event {index} has invalid details."
            )

        event_id = event.get("id")

        if not isinstance(event_id, int):
            errors.append(
                f"Audit event {index} has an invalid ID."
            )
        elif previous_id is not None and event_id <= previous_id:
            errors.append(
                "Audit event IDs are not strictly increasing."
            )

        if isinstance(event_id, int):
            previous_id = event_id

    if errors:
        return {
            "valid": False,
            "errors": errors,
        }

    creation = audit_log[0]
    creation_details = creation["details"]

    if creation["event"] != "response_request_created":
        errors.append("First audit event must record request creation.")

    if creation["actor"] != record.get("requested_by"):
        errors.append("Request creator does not match the response record.")

    if creation_details.get("action") != record.get("action"):
        errors.append("Created action does not match the response record.")

    if creation_details.get("target") != record.get("target"):
        errors.append("Created target does not match the response record.")

    if creation_details.get("status") not in {
        "pending_approval",
        "rejected",
    }:
        errors.append("Created event contains an invalid initial status.")

    if status == "pending_approval":
        if creation_details.get("status") != "pending_approval":
            errors.append("Pending response has an inconsistent initial status.")

        if record.get("decided_by") is not None:
            errors.append("Pending response unexpectedly has a decision actor.")

        if record.get("simulated"):
            errors.append("Pending response cannot be simulated.")

    if status in {"approved", "rejected"}:
        decision = audit_log[1]
        decision_details = decision["details"]

        if decision["actor"] != record.get("decided_by"):
            errors.append("Decision actor does not match the response record.")

        if decision_details.get("new_status") != status:
            errors.append("Decision event does not match the response status.")

        if record.get("decision_at") != decision.get("created_at"):
            errors.append("Decision timestamp does not match the audit event.")

        if record.get("executed") or record.get("simulated"):
            errors.append("Decided response has an invalid execution state.")

    if status == "simulated":
        approval = audit_log[1]
        simulation = audit_log[2]

        if approval["actor"] != record.get("decided_by"):
            errors.append("Simulation approval actor is inconsistent.")

        if approval["details"].get("new_status") != "approved":
            errors.append("Simulation lacks a valid approval event.")

        if record.get("decision_at") != approval.get("created_at"):
            errors.append("Approval timestamp does not match the audit event.")

        if record.get("simulated") is not True:
            errors.append("Simulated status requires simulated=True.")

        if record.get("executed") is not False:
            errors.append("Dry-run simulation must not be executed.")

        simulation_details = simulation["details"]

        if simulation_details.get("simulation_mode") != "dry_run":
            errors.append("Simulation mode must be dry_run.")

        if simulation_details.get("outcome") != "would_block":
            errors.append("Simulation outcome is invalid.")

        for field in (
            "firewall_modified",
            "network_modified",
            "operating_system_command_executed",
            "executed",
        ):
            if simulation_details.get(field) is not False:
                errors.append(
                    f"Simulation safety field {field} must be False."
                )

        if simulation_details.get("simulated") is not True:
            errors.append("Simulation event must record simulated=True.")

    return {
        "valid": not errors,
        "errors": errors,
    }
