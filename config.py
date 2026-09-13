import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "threat_intel.db"

# Telegram Settings
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# RSS & OSINT Feed Sources
FEED_SOURCES = {
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cisco_talos": "https://blog.talosintelligence.com/rss/",
    "unit42": "https://unit42.paloaltonetworks.com/feed/",
    "sentinelone": "https://www.sentinelone.com/blog/feed/",
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
}

# Polling Interval (in seconds) - Default: 15 minutes
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "900"))
