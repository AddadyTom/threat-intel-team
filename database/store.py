import sqlite3
import hashlib
from typing import Optional, List, Dict, Any
from pathlib import Path
import logging
from config import DB_PATH

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ThreatIntelStore")

class ThreatIntelStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Creates table schemas for deduplication and threat history if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Table 1: Track seen fingerprints to guarantee 0 duplicate alerts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS seen_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    source_name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Table 2: Full threat reports history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cve_ids TEXT,
                    malware_families TEXT,
                    mitre_tactics TEXT,
                    full_report_markdown TEXT NOT NULL,
                    alert_sent BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(artifact_id) REFERENCES seen_artifacts(artifact_id)
                );
            """)
            conn.commit()

    @staticmethod
    def generate_artifact_id(raw_identifier: str) -> str:
        """Generates a deterministic SHA256 hex string from raw URL, CVE ID, or malware hash."""
        return hashlib.sha256(raw_identifier.strip().lower().encode("utf-8")).hexdigest()

    def is_artifact_seen(self, artifact_id: str) -> bool:
        """Returns True if the artifact ID is already recorded in the DB."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM seen_artifacts WHERE artifact_id = ?", (artifact_id,))
            return cursor.fetchone() is not None

    def record_artifact(self, artifact_id: str, source_name: str, title: str) -> bool:
        """Records an artifact in seen_artifacts. Returns True if inserted, False if duplicate."""
        if self.is_artifact_seen(artifact_id):
            return False
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO seen_artifacts (artifact_id, source_name, title) VALUES (?, ?, ?)",
                    (artifact_id, source_name, title)
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def save_report(self, artifact_id: str, title: str, severity: str, cve_ids: str,
                    malware_families: str, mitre_tactics: str, full_report: str, alert_sent: bool = True) -> int:
        """Saves an analyzed threat report to persistent history."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threat_reports 
                (artifact_id, title, severity, cve_ids, malware_families, mitre_tactics, full_report_markdown, alert_sent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (artifact_id, title, severity, cve_ids, malware_families, mitre_tactics, full_report, int(alert_sent)))
            conn.commit()
            return cursor.lastrowid

    def get_recent_reports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves recent threat reports from storage."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM threat_reports ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
