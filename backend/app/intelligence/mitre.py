from dataclasses import dataclass


@dataclass(frozen=True)
class MITRETechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    url: str


class MITREAttackMapper:
    """
    Maps AEGIS detection rules and observed behaviours
    to MITRE ATT&CK techniques.
    """

    TECHNIQUES = {
        "T1110": MITRETechnique(
            technique_id="T1110",
            name="Brute Force",
            tactic="Credential Access",
            description=(
                "Adversaries may use brute-force techniques to "
                "gain access to accounts by systematically guessing "
                "passwords or other authentication credentials."
            ),
            url="https://attack.mitre.org/techniques/T1110/",
        ),
        "T1110.001": MITRETechnique(
            technique_id="T1110.001",
            name="Password Guessing",
            tactic="Credential Access",
            description=(
                "Adversaries may guess passwords to gain access "
                "to accounts."
            ),
            url="https://attack.mitre.org/techniques/T1110/001/",
        ),
        "T1110.003": MITRETechnique(
            technique_id="T1110.003",
            name="Password Spraying",
            tactic="Credential Access",
            description=(
                "Adversaries may use one or a small number of "
                "commonly used passwords against many accounts."
            ),
            url="https://attack.mitre.org/techniques/T1110/003/",
        ),
        "T1046": MITRETechnique(
            technique_id="T1046",
            name="Network Service Discovery",
            tactic="Discovery",
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
            description=(
                "Adversaries may use HTTP or HTTPS to communicate "
                "with compromised systems."
            ),
            url="https://attack.mitre.org/techniques/T1071/001/",
        ),
        "T1595": MITRETechnique(
            technique_id="T1595",
            name="Active Scanning",
            tactic="Reconnaissance",
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
            description=(
                "Adversaries may scan ranges of IP addresses "
                "to identify potential targets."
            ),
            url="https://attack.mitre.org/techniques/T1595/001/",
        ),
    }

    RULE_MAPPINGS = {
        "AEGIS-AUTH-001": ["T1110", "T1110.001"],
        "AEGIS-AUTH-002": ["T1110.003"],
        "AEGIS-NET-001": ["T1046"],
    }

    @classmethod
    def get_technique(
        cls,
        technique_id: str,
    ) -> MITRETechnique | None:
        return cls.TECHNIQUES.get(technique_id.upper())

    @classmethod
    def map_detection_rule(
        cls,
        rule_id: str,
    ) -> list[MITRETechnique]:
        technique_ids = cls.RULE_MAPPINGS.get(
            rule_id.upper(),
            [],
        )

        return [
            cls.TECHNIQUES[technique_id]
            for technique_id in technique_ids
            if technique_id in cls.TECHNIQUES
        ]

    @classmethod
    def get_all_techniques(cls) -> list[MITRETechnique]:
        return list(cls.TECHNIQUES.values())

    @classmethod
    def search_techniques(
        cls,
        query: str,
    ) -> list[MITRETechnique]:
        query = query.strip().lower()

        if not query:
            return []

        return [
            technique
            for technique in cls.TECHNIQUES.values()
            if query in technique.name.lower()
            or query in technique.tactic.lower()
            or query in technique.technique_id.lower()
        ]
