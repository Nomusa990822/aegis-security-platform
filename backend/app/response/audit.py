from typing import Any


EXPECTED_EVENTS = {
    "pending_approval": [
        "response_request_created",
    ],
    "approved": [
        "response_request_created",
        "response_approved",
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

    if not audit_log:
        return {
            "valid": False,
            "errors": ["Response has no audit events."],
        }

    response_id = record.get("id")
    alert_id = record.get("alert_id")
    status = record.get("status")

    if status not in {
        "pending_approval",
        "approved",
        "rejected",
        "simulated",
    }:
        errors.append(f"Unsupported response status: {status}")

    if any(not isinstance(event, dict) for event in audit_log):
        errors.append("Every audit event must be an object.")
        return {
            "valid": False,
            "errors": errors,
        }

    event_names = [
        event.get("event")
        for event in audit_log
    ]

    valid_sequences = {
        "pending_approval": [
            ["response_request_created"],
        ],
        "approved": [
            [
                "response_request_created",
                "response_approved",
            ],
        ],
        "rejected": [
            ["response_request_created"],
            [
                "response_request_created",
                "response_rejected",
            ],
        ],
        "simulated": [
            [
                "response_request_created",
                "response_approved",
                "response_simulated",
            ],
        ],
    }

    if (
        status in valid_sequences
        and event_names not in valid_sequences[status]
    ):
        errors.append(
            "Audit event sequence does not match response status."
        )

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

        if not isinstance(event.get("actor"), str) or not event["actor"].strip():
            errors.append(
                f"Audit event {index} has no valid actor."
            )

        if not isinstance(event.get("details"), dict):
            errors.append(
                f"Audit event {index} has invalid details."
            )

        event_id = event.get("id")

        if type(event_id) is not int:
            errors.append(
                f"Audit event {index} has an invalid ID."
            )
        elif previous_id is not None and event_id <= previous_id:
            errors.append(
                "Audit event IDs are not strictly increasing."
            )

        if type(event_id) is int:
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

    initial_status = creation_details.get("status")

    if initial_status not in {
        "pending_approval",
        "rejected",
    }:
        errors.append("Created event contains an invalid initial status.")

    if status == "pending_approval":
        if initial_status != "pending_approval":
            errors.append(
                "Pending response has an inconsistent initial status."
            )

        if record.get("decided_by") is not None:
            errors.append(
                "Pending response unexpectedly has a decision actor."
            )

        if record.get("decision_at") is not None:
            errors.append(
                "Pending response unexpectedly has a decision timestamp."
            )

        if record.get("executed") or record.get("simulated"):
            errors.append("Pending response cannot be executed or simulated.")

    elif status == "rejected" and len(audit_log) == 1:
        if initial_status != "rejected":
            errors.append(
                "Policy-rejected response must have an initial rejected status."
            )

        if record.get("decided_by") is not None:
            errors.append(
                "Policy-rejected response cannot have an approver."
            )

        if record.get("decision_at") is not None:
            errors.append(
                "Policy-rejected response cannot have a decision timestamp."
            )

        if record.get("executed") or record.get("simulated"):
            errors.append(
                "Policy-rejected response cannot be executed or simulated."
            )

    elif status in {"approved", "rejected"}:
        if initial_status != "pending_approval":
            errors.append(
                "Approver decision must follow a pending approval request."
            )

        decision = audit_log[1]
        decision_details = decision["details"]

        if decision["actor"] != record.get("decided_by"):
            errors.append(
                "Decision actor does not match the response record."
            )

        if decision_details.get("new_status") != status:
            errors.append(
                "Decision event does not match the response status."
            )

        if record.get("decision_at") != decision.get("created_at"):
            errors.append(
                "Decision timestamp does not match the audit event."
            )

        if record.get("executed") or record.get("simulated"):
            errors.append(
                "Decided response has an invalid execution state."
            )

    elif status == "simulated":
        if initial_status != "pending_approval":
            errors.append(
                "Simulated response must originate from a pending request."
            )

        approval = audit_log[1]
        simulation = audit_log[2]

        if approval["actor"] != record.get("decided_by"):
            errors.append("Simulation approval actor is inconsistent.")

        if approval["details"].get("new_status") != "approved":
            errors.append("Simulation lacks a valid approval event.")

        if record.get("decision_at") != approval.get("created_at"):
            errors.append(
                "Approval timestamp does not match the audit event."
            )

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