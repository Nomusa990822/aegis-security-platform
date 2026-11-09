from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class MITRETechnique:
    technique_id: str
    name: str
    tactic: str
    tactic_id: str
    description: str
    url: str
    parent_technique_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MITRERuleMapping:
    rule_id: str
    technique_id: str
    confidence: str
    mapping_type: str
    rationale: str
    evidence_requirements: tuple[str, ...]

    def to_dict(self) -> dict:
        result = asdict(self)
        result["evidence_requirements"] = list(
            self.evidence_requirements
        )
        return result


class MITREAttackMapper:
    """
    Curated MITRE ATT&CK Enterprise catalogue and AEGIS rule mappings.

    A mapping represents an analytical association. It does not
    independently establish that adversarial activity occurred.
    """

    TECHNIQUES = {
        "T1110": MITRETechnique(
            technique_id="T1110",
            name="Brute Force",
            tactic="Credential Access",
            tactic_id="TA0006",
            description=(
                "Adversaries may use brute-force techniques to gain "
                "access to accounts by systematically guessing "
                "passwords or other authentication credentials."
            ),
            url="https://attack.mitre.org/techniques/T1110/",
        ),
        "T1110.001": MITRETechnique(
            technique_id="T1110.001",
            name="Password Guessing",
            tactic="Credential Access",
            tactic_id="TA0006",
            description=(
                "Adversaries may guess passwords to gain access "
                "to accounts."
            ),
            url="https://attack.mitre.org/techniques/T1110/001/",
            parent_technique_id="T1110",
        ),
        "T1110.003": MITRETechnique(
            technique_id="T1110.003",
            name="Password Spraying",
            tactic="Credential Access",
            tactic_id="TA0006",
            description=(
                "Adversaries may use one or a small number of "
                "commonly used passwords against many accounts."
            ),
            url="https://attack.mitre.org/techniques/T1110/003/",
            parent_technique_id="T1110",
        ),
        "T1078": MITRETechnique(
            technique_id="T1078",
            name="Valid Accounts",
            tactic="Initial Access",
            tactic_id="TA0001",
            description=(
                "Adversaries may obtain and abuse credentials of existing "
                "accounts to gain initial access, maintain access, or evade "
                "defences."
            ),
            url="https://attack.mitre.org/techniques/T1078/",
        ),
        "T1021": MITRETechnique(
            technique_id="T1021",
            name="Remote Services",
            tactic="Lateral Movement",
            tactic_id="TA0008",
            description=(
                "Adversaries may use valid accounts to log into remote "
                "services, including remote desktop, file sharing, and "
                "remote management services, to move laterally."
            ),
            url="https://attack.mitre.org/techniques/T1021/",
        ),
        "T1046": MITRETechnique(
            technique_id="T1046",
            name="Network Service Discovery",
            tactic="Discovery",
            tactic_id="TA0007",
            description=(
                "Adversaries may attempt to discover services "
                "running on remote hosts."
            ),
            url="https://attack.mitre.org/techniques/T1046/",
        ),
        "T1071": MITRETechnique(
            technique_id="T1071",
            name="Application Layer Protocol",
            tactic="Command and Control",
            tactic_id="TA0011",
            description=(
                "Adversaries may communicate using application "
                "layer protocols to avoid detection."
            ),
            url="https://attack.mitre.org/techniques/T1071/",
        ),
        "T1071.001": MITRETechnique(
            technique_id="T1071.001",
            name="Web Protocols",
            tactic="Command and Control",
            tactic_id="TA0011",
            description=(
                "Adversaries may use HTTP or HTTPS to communicate "
                "with compromised systems."
            ),
            url="https://attack.mitre.org/techniques/T1071/001/",
            parent_technique_id="T1071",
        ),
        "T1595": MITRETechnique(
            technique_id="T1595",
            name="Active Scanning",
            tactic="Reconnaissance",
            tactic_id="TA0043",
            description=(
                "Adversaries may scan victim infrastructure to "
                "identify exploitable systems and services."
            ),
            url="https://attack.mitre.org/techniques/T1595/",
        ),
        "T1595.001": MITRETechnique(
            technique_id="T1595.001",
            name="Scanning IP Blocks",
            tactic="Reconnaissance",
            tactic_id="TA0043",
            description=(
                "Adversaries may scan ranges of IP addresses "
                "to identify potential targets."
            ),
            url="https://attack.mitre.org/techniques/T1595/001/",
            parent_technique_id="T1595",
        ),
    }

    RULE_MAPPINGS = {
        "AEGIS-AUTH-001": [
            MITRERuleMapping(
                rule_id="AEGIS-AUTH-001",
                technique_id="T1110.001",
                confidence="high",
                mapping_type="direct_behavioural_match",
                rationale=(
                    "Repeated authentication failures from one source "
                    "against the same account are consistent with "
                    "password-guessing behaviour."
                ),
                evidence_requirements=(
                    "Correlate failed attempts by source IP and account.",
                    "Validate the authentication event source and timestamps.",
                ),
            ),
        ],
        "AEGIS-AUTH-002": [
            MITRERuleMapping(
                rule_id="AEGIS-AUTH-002",
                technique_id="T1110.003",
                confidence="moderate",
                mapping_type="probable_behavioural_match",
                rationale=(
                    "Authentication failures against multiple accounts "
                    "from one source are consistent with password spraying. "
                    "AEGIS does not currently inspect attempted password "
                    "values, so this remains a behavioural inference."
                ),
                evidence_requirements=(
                    "Confirm failures target multiple distinct accounts.",
                    "Review authentication telemetry for password reuse "
                    "or a small set of repeated passwords, where available.",
                ),
            ),
        ],
        "AEGIS-AUTH-003": [
            MITRERuleMapping(
                rule_id="AEGIS-AUTH-003",
                technique_id="T1110.001",
                confidence="moderate",
                mapping_type="probable_behavioural_match",
                rationale=(
                    "Failed attempts against one account from multiple "
                    "distinct source IPs are consistent with distributed "
                    "password guessing. AEGIS does not inspect attempted "
                    "password values or establish that the sources are "
                    "under common control."
                ),
                evidence_requirements=(
                    "Confirm failures target the same distinct account.",
                    "Review the distinct source IPs and event timestamps.",
                    "Correlate source ownership and authentication context "
                    "before treating the activity as coordinated.",
                ),
            ),
        ],
        "AEGIS-AUTH-004": [
            MITRERuleMapping(
                rule_id="AEGIS-AUTH-004",
                technique_id="T1078",
                confidence="low",
                mapping_type="contextual_candidate",
                rationale=(
                    "A successful authentication after repeated failures "
                    "may indicate that valid credentials were obtained, "
                    "but legitimate user mistakes can produce the same "
                    "sequence. The alert is a triage signal, not proof of "
                    "account compromise."
                ),
                evidence_requirements=(
                    "Verify the successful authentication with the account owner.",
                    "Review available MFA, device, and session context.",
                    "Check whether the preceding failures were expected.",
                ),
            ),
        ],
        "AEGIS-AUTH-005": [
            MITRERuleMapping(
                rule_id="AEGIS-AUTH-005",
                technique_id="T1078",
                confidence="low",
                mapping_type="contextual_candidate",
                rationale=(
                    "Successful authentication to one account from multiple "
                    "distinct source IPs may be consistent with use of valid "
                    "accounts across distributed infrastructure. Shared "
                    "networks, VPNs, proxies, and legitimate travel can produce "
                    "the same pattern; source-IP diversity alone is not proof "
                    "of credential abuse."
                ),
                evidence_requirements=(
                    "Verify the account owner and expected source networks.",
                    "Review available device, session, MFA, and geolocation context.",
                    "Correlate with other authentication and endpoint evidence.",
                ),
            ),
        ],
        "AEGIS-NET-005": [
            MITRERuleMapping(
                rule_id="AEGIS-NET-005",
                technique_id="T1021",
                confidence="low",
                mapping_type="contextual_candidate",
                rationale=(
                    "Rapid connections to multiple hosts on common remote-"
                    "administration ports may be consistent with remote-service "
                    "use during lateral movement. Port numbers alone do not "
                    "confirm the service, successful access, or malicious intent; "
                    "authorised administration and scanning can produce similar "
                    "patterns."
                ),
                evidence_requirements=(
                    "Verify the actual application service and connection outcome.",
                    "Confirm destination assets are internal and identify their owners.",
                    "Check whether the source is an authorised administration host.",
                    "Correlate with authentication, endpoint, and session evidence.",
                ),
            ),
        ],
        "AEGIS-NET-001": [
            MITRERuleMapping(
                rule_id="AEGIS-NET-001",
                technique_id="T1046",
                confidence="high",
                mapping_type="direct_behavioural_match",
                rationale=(
                    "Contacting multiple destination ports on one host "
                    "is consistent with network service discovery."
                ),
                evidence_requirements=(
                    "Review destination ports and target host.",
                    "Correlate connection attempts within the detection window.",
                ),
            ),
        ],
        "AEGIS-NET-002": [
            MITRERuleMapping(
                rule_id="AEGIS-NET-002",
                technique_id="T1046",
                confidence="high",
                mapping_type="direct_behavioural_match",
                rationale=(
                    "Contacting multiple destination hosts on the same "
                    "port is consistent with network service discovery."
                ),
                evidence_requirements=(
                    "Review destination IP addresses and destination port.",
                    "Validate the source and connection sequence.",
                ),
            ),
        ],
        "AEGIS-NET-003": [
            MITRERuleMapping(
                rule_id="AEGIS-NET-003",
                technique_id="T1046",
                confidence="high",
                mapping_type="direct_behavioural_match",
                rationale=(
                    "Contacting numerous destination IP and port "
                    "combinations is consistent with broad network "
                    "service discovery."
                ),
                evidence_requirements=(
                    "Review destination IP and port combinations.",
                    "Correlate the connection activity within the detection window.",
                ),
            ),
        ],
        "AEGIS-NET-004": [
            MITRERuleMapping(
                rule_id="AEGIS-NET-004",
                technique_id="T1071",
                confidence="low",
                mapping_type="contextual_candidate",
                rationale=(
                    "Regular connection intervals may be consistent "
                    "with beaconing. Periodicity alone does not establish "
                    "command-and-control activity or identify an "
                    "application-layer protocol."
                ),
                evidence_requirements=(
                    "Identify the application-layer protocol.",
                    "Inspect connection metadata and destination reputation.",
                    "Seek additional evidence of command-and-control behaviour.",
                ),
            ),
        ],
    }

    @classmethod
    def get_technique(
        cls,
        technique_id: str,
    ) -> MITRETechnique | None:
        if not technique_id:
            return None

        return cls.TECHNIQUES.get(technique_id.strip().upper())

    @classmethod
    def get_all_techniques(cls) -> list[MITRETechnique]:
        return list(cls.TECHNIQUES.values())

    @classmethod
    def search_techniques(
        cls,
        query: str,
    ) -> list[MITRETechnique]:
        if not query or not query.strip():
            return []

        query = query.strip().lower()

        return [
            technique
            for technique in cls.TECHNIQUES.values()
            if query in technique.name.lower()
            or query in technique.tactic.lower()
            or query in technique.tactic_id.lower()
            or query in technique.technique_id.lower()
            or query in technique.description.lower()
        ]

    @classmethod
    def get_rule_mapping(
        cls,
        rule_id: str,
    ) -> dict:
        normalized_rule_id = rule_id.strip().upper()

        mappings = cls.RULE_MAPPINGS.get(
            normalized_rule_id,
            [],
        )

        results = []

        for mapping in mappings:
            technique = cls.get_technique(
                mapping.technique_id
            )

            if technique is None:
                continue

            results.append({
                **mapping.to_dict(),
                "technique": technique.to_dict(),
                "parent_technique": (
                    cls.get_technique(
                        technique.parent_technique_id
                    ).to_dict()
                    if technique.parent_technique_id
                    else None
                ),
            })

        return {
            "rule_id": normalized_rule_id,
            "mapped": bool(results),
            "mapping_count": len(results),
            "mappings": results,
        }

    @classmethod
    def get_all_rule_mappings(cls) -> list[dict]:
        return [
            cls.get_rule_mapping(rule_id)
            for rule_id in cls.RULE_MAPPINGS
        ]

    @classmethod
    def map_detection_rule(
        cls,
        rule_id: str,
    ) -> list[MITRETechnique]:
        """
        Backward-compatible helper returning mapped techniques.
        """
        mapping = cls.get_rule_mapping(rule_id)

        return [
            cls.TECHNIQUES[item["technique_id"]]
            for item in mapping["mappings"]
        ]

    @classmethod
    def get_techniques_for_rule(
        cls,
        rule_id: str,
    ) -> list[MITRETechnique]:
        """
        Backward-compatible alias for older callers.
        """
        return cls.map_detection_rule(rule_id)
