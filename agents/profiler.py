import logging
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ProfilerAgent")

class ProfilerAgent:
    """Agent responsible for mapping analyzed threats to MITRE ATT&CK techniques and attributing threat actors."""

    # MITRE ATT&CK Mapping Dictionary
    ATTACK_PATTERNS = {
        "T1190": ("Exploit Public-Facing Application", ["cve", "remote code execution", "vulnerability", "rce", "exploit"]),
        "T1566": ("Phishing", ["phishing", "email", "spearphishing", "attachment", "malicious link"]),
        "T1059": ("Command and Scripting Interpreter", ["powershell", "cmd.exe", "bash", "python", "script"]),
        "T1486": ("Data Encrypted for Impact (Ransomware)", ["ransomware", "encrypt", "lockbit", "blackcat", "alphv", "ransom"]),
        "T1555": ("Credentials from Password Stores", ["stealer", "infostealer", "browser credentials", "mimikatz", "passwords"]),
        "T1071": ("Application Layer Protocol (C2)", ["c2 server", "command and control", "http beacon", "dns tunneling"])
    }

    KNOWN_APT_GROUPS = [
        "APT28", "APT29", "Lazarus Group", "FIN7", "Scattered Spider", "LockBit", "BlackCat", "Volt Typhoon", "Cozy Bear"
    ]

    def profile(self, analyzed_item: Dict[str, Any]) -> Dict[str, Any]:
        """Profiles threat by identifying MITRE ATT&CK techniques and potential APT attribution."""
        text = f"{analyzed_item['title']} {analyzed_item['summary_snippet']} {' '.join(analyzed_item['malware_types'])}".lower()
        
        mitre_tactics = []
        for tech_id, (tech_name, keywords) in self.ATTACK_PATTERNS.items():
            if any(kw in text for kw in keywords):
                mitre_tactics.append(f"{tech_id}: {tech_name}")

        attributed_groups = []
        for group in self.KNOWN_APT_GROUPS:
            if group.lower() in text:
                attributed_groups.append(group)

        profiled_result = {
            **analyzed_item,
            "mitre_tactics": mitre_tactics or ["T1190: Exploit Public-Facing Application"],
            "attributed_groups": attributed_groups or ["Unattributed / Generic Threat"]
        }

        logger.info(f"Profiled '{analyzed_item['title'][:40]}...': MITRE Tags={len(mitre_tactics)}, Groups={profiled_result['attributed_groups']}")
        return profiled_result
