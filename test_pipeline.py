import asyncio
import pytest
from database.store import ThreatIntelStore
from agents.collector import CollectorAgent
from agents.analyst import AnalystAgent
from agents.profiler import ProfilerAgent
from agents.reporter import ReporterAgent

@pytest.mark.asyncio
async def test_store_deduplication(tmp_path):
    db_file = tmp_path / "test_threat.db"
    store = ThreatIntelStore(db_path=db_file)
    
    art_id = store.generate_artifact_id("https://example.com/test-threat")
    
    # First record should succeed
    res1 = store.record_artifact(art_id, "TestFeed", "Test Title")
    assert res1 is True
    
    # Second record with same artifact_id must fail (0 duplicate guarantee)
    res2 = store.record_artifact(art_id, "TestFeed", "Test Title")
    assert res2 is False

def test_analyst_ioc_extraction():
    analyst = AnalystAgent()
    sample_text = "Critical zero-day RCE in Apache! CVE-2026-9999. Malicious IP 185.220.101.5 and hash 44d88612fea8a8f36de82e1278abb02f"
    
    raw_item = {
        "artifact_id": "test_123",
        "title": "Apache Zero Day",
        "source": "Cisco Talos",
        "url": "https://example.com/apache",
        "summary": sample_text,
        "raw_content": sample_text
    }
    
    result = analyst.analyze(raw_item)
    assert result["severity"] == "CRITICAL"
    assert "CVE-2026-9999" in result["cve_ids"]
    assert "185.220.101.5" in result["iocs"]["ips"]
    assert "44d88612fea8a8f36de82e1278abb02f" in result["iocs"]["md5_hashes"]

def test_profiler_mitre_mapping():
    profiler = ProfilerAgent()
    analyzed_item = {
        "title": "LockBit Ransomware Uses PowerShell for Initial Access",
        "summary_snippet": "Lockbit ransomware group executed powershell scripts",
        "malware_types": ["Ransomware"],
        "severity": "HIGH",
        "cve_ids": []
    }
    
    result = profiler.profile(analyzed_item)
    assert any("T1486" in t for t in result["mitre_tactics"])  # Ransomware
    assert any("T1059" in t for t in result["mitre_tactics"])  # PowerShell
    assert "LockBit" in result["attributed_groups"]

@pytest.mark.asyncio
async def test_full_pipeline_dry_run(tmp_path):
    db_file = tmp_path / "test_pipeline.db"
    store = ThreatIntelStore(db_path=db_file)
    collector = CollectorAgent(store)
    analyst = AnalystAgent()
    profiler = ProfilerAgent()
    reporter = ReporterAgent(store)

    items = await collector.collect_unseen_intelligence()
    assert isinstance(items, list)

    if items:
        test_item = items[0]
        analyzed = analyst.analyze(test_item)
        profiled = profiler.profile(analyzed)
        success = await reporter.process_and_report(profiled)
        assert success is True

        # Second attempt should be deduplicated
        success_dup = await reporter.process_and_report(profiled)
        assert success_dup is False

if __name__ == "__main__":
    print("Running integration test manually...")
    asyncio.run(test_full_pipeline_dry_run(Path("./data")))
    print("✅ All manual tests passed!")
