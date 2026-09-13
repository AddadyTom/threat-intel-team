import httpx
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Any
from config import FEED_SOURCES
from database.store import ThreatIntelStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CollectorAgent")

class CollectorAgent:
    """Agent responsible for gathering raw threat intelligence from RSS feeds, CISA KEV, and APIs."""

    def __init__(self, store: ThreatIntelStore):
        self.store = store

    async def fetch_cisa_kev(self) -> List[Dict[str, Any]]:
        """Fetches CISA Known Exploited Vulnerabilities feed."""
        items = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(FEED_SOURCES["cisa_kev"])
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    for vuln in vulnerabilities[:10]:  # Inspect recent 10 entries
                        cve_id = vuln.get("cveID", "")
                        title = f"{cve_id}: {vuln.get('vulnerabilityName', '')}"
                        raw_id = f"cisa_{cve_id}"
                        items.append({
                            "raw_id": raw_id,
                            "source": "CISA KEV",
                            "title": title,
                            "cve_id": cve_id,
                            "summary": vuln.get("shortDescription", ""),
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            "raw_content": f"Vendor: {vuln.get('vendorProject')}, Product: {vuln.get('product')}, Action: {vuln.get('requiredAction')}"
                        })
        except Exception as e:
            logger.error(f"Error fetching CISA KEV feed: {e}")
        return items

    async def fetch_rss_feed(self, source_name: str, feed_url: str) -> List[Dict[str, Any]]:
        """Fetches and parses an RSS feed from vendor research blogs."""
        items = []
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                headers = {"User-Agent": "Mozilla/5.0 (ThreatIntelAgent/1.0)"}
                resp = await client.get(feed_url, headers=headers)
                if resp.status_code == 200:
                    root = ET.fromstring(resp.content)
                    # Check channel -> item (RSS 2.0) or entry (Atom)
                    channel = root.find("channel")
                    feed_items = channel.findall("item") if channel is not None else root.findall("{http://www.w3.org/2005/Atom}entry")
                    
                    for item in feed_items[:5]:  # Process top 5 recent posts per feed
                        title_el = item.find("title") or item.find("{http://www.w3.org/2005/Atom}title")
                        link_el = item.find("link") or item.find("{http://www.w3.org/2005/Atom}link")
                        desc_el = item.find("description") or item.find("{http://www.w3.org/2005/Atom}summary")
                        
                        title = title_el.text if title_el is not None else "Untitled"
                        link = link_el.text if link_el is not None and link_el.text else (link_el.attrib.get("href", "") if link_el is not None else "")
                        desc = desc_el.text if desc_el is not None else ""
                        
                        if link:
                            items.append({
                                "raw_id": link,
                                "source": source_name,
                                "title": title.strip(),
                                "summary": desc[:500] if desc else title,
                                "url": link.strip(),
                                "raw_content": f"Title: {title}\nURL: {link}\nSummary Snippet: {desc[:1000] if desc else ''}"
                            })
        except Exception as e:
            logger.error(f"Error fetching RSS feed {source_name}: {e}")
        return items

    async def collect_unseen_intelligence(self) -> List[Dict[str, Any]]:
        """Collects feeds from all sources and filters out already seen items via the storage engine."""
        all_raw_items = []
        
        # 1. Fetch CISA KEV
        cisa_items = await self.fetch_cisa_kev()
        all_raw_items.extend(cisa_items)

        # 2. Fetch RSS feeds (Cisco Talos, Mandiant, Unit 42, SentinelOne, BleepingComputer)
        for name, url in FEED_SOURCES.items():
            if name == "cisa_kev":
                continue
            rss_items = await self.fetch_rss_feed(name.capitalize(), url)
            all_raw_items.extend(rss_items)

        unseen_items = []
        for item in all_raw_items:
            artifact_id = ThreatIntelStore.generate_artifact_id(item["raw_id"])
            if not self.store.is_artifact_seen(artifact_id):
                item["artifact_id"] = artifact_id
                unseen_items.append(item)

        logger.info(f"Collected {len(all_raw_items)} total items. Found {len(unseen_items)} NEW unseen intelligence items.")
        return unseen_items
