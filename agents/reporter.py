import httpx
import logging
import json
from typing import Dict, Any
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
from database.store import ThreatIntelStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ReporterAgent")

class ReporterAgent:
    """Agent responsible for formatting Threat Intel briefs, recording reports to SQLite DB, and delivering Telegram alerts."""

    def __init__(self, store: ThreatIntelStore):
        self.store = store

    @staticmethod
    def format_markdown_report(item: Dict[str, Any]) -> str:
        """Formats threat intelligence into clean Telegram-compatible Markdown."""
        severity_emoji = {
            "CRITICAL": "🚨 **CRITICAL THREAT ALERT**",
            "HIGH": "⚠️ **HIGH SEVERITY ALERT**",
            "MEDIUM": "🛡️ **SECURITY THREAT NOTICE**",
            "LOW": "ℹ️ **SECURITY INFORMATIONAL**"
        }.get(item["severity"], "🛡️ **SECURITY NOTICE**")

        cve_str = ", ".join(item["cve_ids"]) if item["cve_ids"] else "None specified"
        mitre_str = "\n".join([f"  • {t}" for t in item["mitre_tactics"]])
        apt_str = ", ".join(item["attributed_groups"])
        
        # IOC summary
        iocs = item.get("iocs", {})
        ioc_bullets = []
        if iocs.get("cves"):
            ioc_bullets.append(f"• **CVEs**: {', '.join(iocs['cves'])}")
        if iocs.get("sha256_hashes"):
            ioc_bullets.append(f"• **Hashes (SHA256)**: {', '.join(iocs['sha256_hashes'][:2])}")
        if iocs.get("ips"):
            ioc_bullets.append(f"• **IPs**: {', '.join(iocs['ips'][:3])}")

        ioc_section = "\n".join(ioc_bullets) if ioc_bullets else "No static IOCs extracted"

        report = f"""{severity_emoji}

📌 **Title**: {item['title']}
🏢 **Source**: {item['source']}
⚖️ **Severity**: `{item['severity']}`

📋 **Summary**:
{item['summary_snippet']}

🎯 **CVE Identifiers**: `{cve_str}`
🕵️ **Threat Actor / Attribution**: {apt_str}

🧱 **MITRE ATT&CK Tactics**:
{mitre_str}

🔍 **Extracted IOCs**:
{ioc_section}

🔗 **Full Reference**: [Read Original Report]({item['url']})
"""
        return report

    async def send_telegram_alert(self, markdown_text: str) -> bool:
        """Sends a Markdown-formatted message via Telegram Bot API."""
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            logger.warning("Telegram Bot Token or Chat ID not set. Skipping live Telegram message (Dry Run Mode).")
            return False

        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": markdown_text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": False
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    logger.info("Telegram alert sent successfully.")
                    return True
                else:
                    logger.error(f"Telegram API returned status {resp.status_code}: {resp.text}")
                    return False
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
            return False

    async def process_and_report(self, profiled_item: Dict[str, Any]) -> bool:
        """Saves artifact to seen DB, records full report, and dispatches Telegram alert."""
        artifact_id = profiled_item["artifact_id"]
        
        # Format markdown
        markdown_report = self.format_markdown_report(profiled_item)
        
        # 1. Record artifact in seen database
        inserted = self.store.record_artifact(
            artifact_id=artifact_id,
            source_name=profiled_item["source"],
            title=profiled_item["title"]
        )

        if not inserted:
            logger.info(f"Artifact {artifact_id} was already recorded. Skipping alert.")
            return False

        # 2. Send Telegram alert
        alert_sent = await self.send_telegram_alert(markdown_report)

        # 3. Save report to DB history
        self.store.save_report(
            artifact_id=artifact_id,
            title=profiled_item["title"],
            severity=profiled_item["severity"],
            cve_ids=json.dumps(profiled_item["cve_ids"]),
            malware_families=json.dumps(profiled_item["malware_types"]),
            mitre_tactics=json.dumps(profiled_item["mitre_tactics"]),
            full_report=markdown_report,
            alert_sent=alert_sent
        )

        logger.info(f"Report for '{profiled_item['title'][:40]}...' processed and saved to persistent DB.")
        return True
