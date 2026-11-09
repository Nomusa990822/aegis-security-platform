from app.intelligence.mitre import MITREAttackMapper


def test_technique_lookup_is_case_insensitive():
    technique = MITREAttackMapper.get_technique("t1046")

    assert technique is not None
    assert technique.name == "Network Service Discovery"
    assert technique.tactic_id == "TA0007"


def test_unknown_technique_returns_none():
    assert MITREAttackMapper.get_technique("T9999") is None


def test_all_eight_detection_rules_have_mappings():
    expected_rule_ids = {
        "AEGIS-AUTH-001",
        "AEGIS-AUTH-002",
        "AEGIS-NET-001",
        "AEGIS-NET-002",
        "AEGIS-NET-003",
        "AEGIS-NET-004",
        "AEGIS-AUTH-003",
        "AEGIS-AUTH-004",
    }

    mappings = MITREAttackMapper.get_all_rule_mappings()

    actual_rule_ids = {
        item["rule_id"]
        for item in mappings
    }

    assert actual_rule_ids == expected_rule_ids
    assert all(item["mapped"] for item in mappings)


def test_brute_force_maps_to_password_guessing():
    mapping = MITREAttackMapper.get_rule_mapping(
        "AEGIS-AUTH-001"
    )

    assert mapping["mapped"] is True
    assert mapping["mappings"][0]["technique_id"] == "T1110.001"
    assert (
        mapping["mappings"][0]["technique"]["parent_technique_id"]
        == "T1110"
    )


def test_password_spraying_mapping_discloses_evidence_limitation():
    mapping = MITREAttackMapper.get_rule_mapping(
        "AEGIS-AUTH-002"
    )

    result = mapping["mappings"][0]

    assert result["technique_id"] == "T1110.003"
    assert result["confidence"] == "moderate"
    assert "does not currently inspect attempted password values" in (
        result["rationale"]
    )


def test_network_discovery_rules_map_to_t1046():
    for rule_id in (
        "AEGIS-NET-001",
        "AEGIS-NET-002",
        "AEGIS-NET-003",
    ):
        mapping = MITREAttackMapper.get_rule_mapping(rule_id)

        assert mapping["mapped"] is True
        assert mapping["mappings"][0]["technique_id"] == "T1046"


def test_beaconing_mapping_is_contextual_not_confirmed():
    mapping = MITREAttackMapper.get_rule_mapping(
        "AEGIS-NET-004"
    )

    result = mapping["mappings"][0]

    assert result["technique_id"] == "T1071"
    assert result["confidence"] == "low"
    assert result["mapping_type"] == "contextual_candidate"


def test_rule_mapping_handles_unknown_rule():
    mapping = MITREAttackMapper.get_rule_mapping(
        "AEGIS-UNKNOWN-001"
    )

    assert mapping["mapped"] is False
    assert mapping["mapping_count"] == 0
    assert mapping["mappings"] == []


def test_technique_search_finds_tactics_and_names():
    results = MITREAttackMapper.search_techniques(
        "credential access"
    )

    assert results
    assert all(
        technique.tactic == "Credential Access"
        for technique in results
    )


def test_empty_technique_search_returns_no_results():
    assert MITREAttackMapper.search_techniques("   ") == []



def test_distributed_password_guessing_maps_to_password_guessing():
    mapping = MITREAttackMapper.get_rule_mapping("AEGIS-AUTH-003")
    result = mapping["mappings"][0]

    assert result["technique_id"] == "T1110.001"
    assert result["confidence"] == "moderate"
    assert "multiple" in result["rationale"]


def test_success_after_failures_maps_to_valid_accounts_with_caveat():
    mapping = MITREAttackMapper.get_rule_mapping("AEGIS-AUTH-004")
    result = mapping["mappings"][0]

    assert result["technique_id"] == "T1078"
    assert result["confidence"] == "moderate"
    assert "not proof of" in result["rationale"]
