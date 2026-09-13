import sys
import json
import sqlite3
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from config import DB_PATH

def load_reports(limit=50):
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.*, s.source_name 
        FROM threat_reports r 
        LEFT JOIN seen_artifacts s ON r.artifact_id = s.artifact_id 
        ORDER BY r.created_at DESC LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def print_cli_table():
    reports = load_reports()
    if not reports:
        print("📁 Database is empty or threat_intel.db was not found.")
        return

    print("\n" + "="*80)
    print(f"🛡️  THREAT INTELLIGENCE DATABASE BROWSER ({len(reports)} Reports Found)")
    print("="*80 + "\n")

    for idx, r in enumerate(reports, 1):
        sev = r['severity']
        badge = "🚨 [CRITICAL]" if sev == "CRITICAL" else ("⚠️ [HIGH]" if sev == "HIGH" else "🛡️ [MEDIUM]")
        cves = json.loads(r['cve_ids']) if r['cve_ids'] else []
        cve_str = ", ".join(cves) if cves else "N/A"
        
        print(f"{idx:2d}. {badge:13s} | {r['title'][:55]}...")
        print(f"    ├─ Source: {r.get('source_name', 'N/A')} | Date: {r['created_at']} | CVEs: {cve_str}")
        print(f"    └─ ID: {r['artifact_id'][:12]}...")
        print("-" * 80)

    print("\nTip: Run 'python3 browse_db.py --report 1' to view full details for item #1.\n")

def print_report_detail(index):
    reports = load_reports()
    if not (1 <= index <= len(reports)):
        print(f"Error: Report index {index} out of range (1 - {len(reports)}).")
        return
    r = reports[index - 1]
    print("\n" + "="*80)
    print(f"DETAILS FOR REPORT #{index}")
    print("="*80)
    print(r['full_report_markdown'])
    print("="*80 + "\n")

class WebDashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        reports = load_reports(100)
        
        cards_html = ""
        for r in reports:
            sev = r['severity']
            color = "#ef4444" if sev == "CRITICAL" else ("#f97316" if sev == "HIGH" else "#3b82f6")
            cves = json.loads(r['cve_ids']) if r['cve_ids'] else []
            mitre = json.loads(r['mitre_tactics']) if r['mitre_tactics'] else []
            
            cve_tags = "".join([f'<span class="tag cve">{c}</span>' for c in cves])
            mitre_tags = "".join([f'<span class="tag mitre">{m}</span>' for m in mitre])
            
            cards_html += f"""
            <div class="card">
                <div class="card-header">
                    <span class="badge" style="background-color: {color};">{sev}</span>
                    <span class="source">{r.get('source_name', 'OSINT')}</span>
                    <span class="date">{r['created_at']}</span>
                </div>
                <h3>{r['title']}</h3>
                <div class="tags">{cve_tags}{mitre_tags}</div>
                <details>
                    <summary>View Full Report Brief</summary>
                    <pre>{r['full_report_markdown']}</pre>
                </details>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Threat Intel DB Browser</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .header {{ max-width: 1000px; margin: 0 auto 30px; border-bottom: 1px solid #334155; padding-bottom: 15px; }}
        .container {{ max-width: 1000px; margin: 0 auto; display: flex; flex-direction: column; gap: 15px; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 20px; border: 1px solid #334155; }}
        .card-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; font-size: 0.85rem; color: #94a3b8; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-weight: bold; color: white; font-size: 0.75rem; }}
        h3 {{ margin: 0 0 10px 0; color: #38bdf8; font-size: 1.1rem; }}
        .tags {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }}
        .tag {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }}
        .cve {{ background: #374151; color: #fbbf24; border: 1px solid #4b5563; }}
        .mitre {{ background: #1e1b4b; color: #a5b4fc; border: 1px solid #312e81; }}
        details {{ background: #0f172a; border-radius: 6px; padding: 10px; color: #cbd5e1; cursor: pointer; }}
        summary {{ font-weight: 500; color: #38bdf8; }}
        pre {{ white-space: pre-wrap; font-family: monospace; font-size: 0.85rem; margin-top: 10px; color: #e2e8f0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Threat Intelligence Database Browser</h1>
        <p>Browsing <code>data/threat_intel.db</code> • {len(reports)} Total Analyzed Reports</p>
    </div>
    <div class="container">
        {cards_html or "<p>No threat reports in database yet.</p>"}
    </div>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

def start_web_browser(port=8080):
    server = HTTPServer(("0.0.0.0", port), WebDashboardHandler)
    print(f"\n🌐 Web Threat Intel DB Browser running at: http://localhost:{port}")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb browser stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Browse threat_intel.db contents")
    parser.add_argument("--web", action="store_true", help="Start web browser dashboard on port 8080")
    parser.add_argument("--port", type=int, default=8080, help="Web server port (default 8080)")
    parser.add_argument("--report", type=int, help="View detailed markdown report by item index number")
    
    args = parser.parse_args()
    
    if args.web:
        start_web_browser(args.port)
    elif args.report:
        print_report_detail(args.report)
    else:
        print_cli_table()
