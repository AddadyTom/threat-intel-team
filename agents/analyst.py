import re
import logging
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AnalystAgent")

class AnalystAgent:
    """Agent responsible for analyzing raw threat intelligence, extracting IOCs, CVSS metrics, and malware behavior."""

    @staticmethod
    def extract_iocs(text: str) -> Dict[str, List[str]]:
        """Regex-based IOC extraction for CVEs, IPv4 addresses, domain names, and file hashes (MD5/SHA256)."""
        cves = list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))
        sha256s = list(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text)))
        md5s = list(set(re.findall(r"\b[a-fA-F0-9]{32}\b", text)))
        ips = list(set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)))
        
        # Exclude common false positive IPs like 127.0.0.1 or 0.0.0.0
        filtered_ips = [ip for ip in ips if not (ip.startswith("127.") or ip.startswith("0.") or ip.startswith("192.168."))]

        return {
            "cves": [c.upper() for c in cves],
            "sha256_hashes": sha256s,
            "md5_hashes": md5s,
            "ips": filtered_ips
        }

    def analyze(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzes raw item content to evaluate severity, vulnerability metrics, and malware traits."""
        content = f"{item.get('title', '')} {item.get('summary', '')} {item.get('raw_content', '')}"
        iocs = self.extract_iocs(content)
        
        # Simple heuristic severity evaluation (will be enriched by LLM prompt in main pipeline)
        severity = "MEDIUM"
        cves_found = iocs["cves"] or ([item.get("cve_id")] if item.get("cve_id") else [])
        
        if cves_found or "zero-day" in content.lower() or "ransomware" in content.lower() or "critical" in content.lower():
            severity = "HIGH"
        if "remote code execution" in content.lower() or "unauthenticated" in content.lower() or "active exploitation" in content.lower():
            severity = "CRITICAL"

        # Detect malware family keywords
        malware_types = []
        for kw in ["ransomware", "stealer", "trojan", "rat", "backdoor", "wiper", "loader"]:
            if kw in content.lower():
                malware_types.append(kw.capitalize())

        analysis_result = {
            "artifact_id": item["artifact_id"],
            "title": item["title"],
            "source": item["source"],
            "url": item["url"],
            "severity": severity,
            "cve_ids": list(set(cves_found)),
            "malware_types": list(set(malware_types)),
            "iocs": iocs,
            "summary_snippet": item["summary"][:300]
        }
        
        logger.info(f"Analyzed '{item['title'][:40]}...': Severity={severity}, CVEs={len(analysis_result['cve_ids'])}, IOCs={len(iocs['sha256_hashes']) + len(iocs['ips'])}")
        return analysis_result
