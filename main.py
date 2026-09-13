import asyncio
import sys
import logging
from config import POLL_INTERVAL
from database.store import ThreatIntelStore
from agents.collector import CollectorAgent
from agents.analyst import AnalystAgent
from agents.profiler import ProfilerAgent
from agents.reporter import ReporterAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("CTITeamLead")

async def run_threat_intel_pipeline(store: ThreatIntelStore, collector: CollectorAgent,
                                   analyst: AnalystAgent, profiler: ProfilerAgent, reporter: ReporterAgent):
    """Executes a single cycle of the CTI Multi-Agent pipeline."""
    logger.info("=== Starting CTI Multi-Agent Pipeline Cycle ===")
    
    # 1. Collector Agent: Gather unseen intelligence
    unseen_items = await collector.collect_unseen_intelligence()
    if not unseen_items:
        logger.info("No new intelligence items found in this cycle.")
        return

    logger.info(f"Processing {len(unseen_items)} new intelligence items...")

    # 2. Process each item through Analyst -> Profiler -> Reporter Agents
    processed_count = 0
    for item in unseen_items:
        try:
            # Analyst Agent
            analyzed = analyst.analyze(item)
            
            # Profiler Agent
            profiled = profiler.profile(analyzed)
            
            # Reporter Agent
            success = await reporter.process_and_report(profiled)
            if success:
                processed_count += 1
        except Exception as e:
            logger.error(f"Error processing item '{item.get('title', '')}': {e}", exc_info=True)

    logger.info(f"=== Pipeline Cycle Finished. Successfully alerted & stored {processed_count} new threats. ===")

async def main():
    logger.info("Initializing Threat Intelligence Multi-Agent System...")
    
    # 1. Persistent Storage
    store = ThreatIntelStore()
    
    # 2. Initialize Agents
    collector = CollectorAgent(store)
    analyst = AnalystAgent()
    profiler = ProfilerAgent()
    reporter = ReporterAgent(store)

    # Check for single execution flag
    run_once = "--once" in sys.argv

    if run_once:
        logger.info("Running in Single-Cycle mode (--once)...")
        await run_threat_intel_pipeline(store, collector, analyst, profiler, reporter)
    else:
        logger.info(f"Starting 24/7 Monitoring Loop (Polling every {POLL_INTERVAL} seconds)...")
        while True:
            await run_threat_intel_pipeline(store, collector, analyst, profiler, reporter)
            await asyncio.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    asyncio.run(main())
