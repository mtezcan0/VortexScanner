import os
import datetime
import html

def generate_reports(target, results_dict):
    if not results_dict:
        return None

    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_dir = os.path.join(base_dir, "reports")
    
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    
    total_scanned = len(results_dict)
    active_sites = sum(1 for data in results_dict.values() if data.get('status') == 200)
    
    total_forms = 0
    total_vulns = 0
    sqli_count = 0
    xss_count = 0

    for data in results_dict.values():
        findings = data.get('findings', {})
        total_forms += findings.get('forms_found', 0)
        vulns = findings.get('vulnerabilities', [])
        total_vulns += len(vulns)
        for v in vulns:
            v_type = str(v.get('type')).lower()
            if "sql" in v_type: sqli_count += 1
            if "xss" in v_type: xss_count += 1

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    filename = os.path.join(report_dir, f"{target}_vortex_report_{file_ts}.html")

    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vortex Scan: {target}</title>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg: #0d1117; 
                --card-bg: #161b22; 
                --border: #30363d; 
                --text-main: #c9d1d9; 
                --text-muted: #8b949e;
                --accent: #58a6ff; 
                --success: #238636; 
                --danger: #f85149; 
                --warning: #d29922;
                --code-bg: #0d1117;
            }}
            body {{ font-family: 'Inter', sans-serif; background-color: var(--bg); color: var(--text-main); margin: 0; padding: 40px; line-height: 1.5; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            
            /* Header */
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; }}
            .brand h1 {{ margin: 0; font-size: 24px; letter-spacing: -0.5px; background: linear-gradient(90deg, #58a6ff, #a371f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
            .meta {{ text-align: right; font-size: 13px; color: var(--text-muted); }}

            /* Stats Cards */
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 40px; }}
            .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); padding: 20px; border-radius: 8px; transition: transform 0.2s; }}
            .stat-card:hover {{ transform: translateY(-2px); border-color: var(--accent); }}
            .stat-value {{ font-size: 28px; font-weight: 800; display: block; margin-bottom: 5px; }}
            .stat-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); font-weight: 600; }}
            
            /* Table */
            .table-container {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th {{ background: #21262d; padding: 15px; text-align: left; font-size: 12px; color: var(--text-muted); text-transform: uppercase; border-bottom: 1px solid var(--border); }}
            td {{ padding: 15px; border-bottom: 1px solid var(--border); vertical-align: top; }}
            tr:last-child td {{ border-bottom: none; }}
            
            /* Status Badges */
            .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }}
            .badge-live {{ background: rgba(35, 134, 54, 0.15); color: #3fb950; border: 1px solid rgba(35, 134, 54, 0.4); }}
            .badge-dead {{ background: rgba(248, 81, 73, 0.15); color: var(--danger); border: 1px solid rgba(248, 81, 73, 0.4); }}
            
            /* Vulnerabilities */
            .vuln-box {{ margin-top: 10px; background: rgba(13, 17, 23, 0.5); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }}
            .vuln-item {{ padding: 10px; border-bottom: 1px solid var(--border); font-size: 13px; display: flex; align-items: baseline; gap: 10px; }}
            .vuln-item:last-child {{ border-bottom: none; }}
            .vuln-type {{ font-weight: bold; color: var(--danger); min-width: 120px; }}
            .vuln-payload {{ font-family: 'JetBrains Mono', monospace; color: var(--accent); background: rgba(88, 166, 255, 0.1); padding: 2px 6px; border-radius: 4px; word-break: break-all; }}
            
            .empty-state {{ color: var(--text-muted); font-style: italic; font-size: 13px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="brand">
                    <h1>VORTEX SCANNER</h1>
                    <div style="margin-top:5px; font-size:14px;">Target: <span style="color:var(--accent)">{target}</span></div>
                </div>
                <div class="meta">
                    <div>Scan Date: {timestamp}</div>
                    <div>Report ID: #{file_ts}</div>
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <span class="stat-value" style="color: var(--text-main)">{total_scanned}</span>
                    <span class="stat-label">Total Domains</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value" style="color: var(--success)">{active_sites}</span>
                    <span class="stat-label">Active Hosts</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value" style="color: var(--warning)">{total_forms}</span>
                    <span class="stat-label">Forms Found</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value" style="color: var(--danger)">{total_vulns}</span>
                    <span class="stat-label">Critical Vulns</span>
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 25%;">Domain / Endpoint</th>
                            <th style="width: 15%;">IP Address</th>
                            <th style="width: 10%;">Status</th>
                            <th style="width: 50%;">Security Findings</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    for sub, data in results_dict.items():
        findings = data.get('findings', {})
        vulns = findings.get('vulnerabilities', [])
        status = data.get('status')
        ip = data.get('ip', 'N/A')
        
        status_html = f'<span class="badge badge-live">LIVE ({status})</span>' if status == 200 else f'<span class="badge badge-dead">{status}</span>'
        
        html_content += f"""
                        <tr>
                            <td style="font-weight: 600; color: var(--accent);">{sub}</td>
                            <td style="font-family: 'JetBrains Mono', monospace; font-size: 13px;">{ip}</td>
                            <td>{status_html}</td>
                            <td>
        """
        
        
        forms_found = findings.get('forms_found', 0)
        if forms_found > 0:
             html_content += f'<div style="margin-bottom:8px; font-size:12px; color:var(--success);">✓ {forms_found} form(s) discovered</div>'

        
        if vulns:
            html_content += '<div class="vuln-box">'
            for v in vulns:
                v_type = html.escape(str(v.get('type', 'Unknown')))
                v_payload = html.escape(str(v.get('payload', 'N/A')))
                v_param = html.escape(str(v.get('parameter', 'unknown')))
                
                html_content += f"""
                    <div class="vuln-item">
                        <span class="vuln-type">⚠️ {v_type}</span>
                        <span style="color:var(--text-muted); font-size:12px;">param: {v_param}</span>
                        <span class="vuln-payload">{v_payload}</span>
                    </div>
                """
            html_content += '</div>'
        elif status == 200 and forms_found == 0:
            html_content += '<span class="empty-state">No attack surface found.</span>'
        
        html_content += "</td></tr>"

    html_content += """
                    </tbody>
                </table>
            </div>
            
            <div style="margin-top: 40px; text-align: center; color: var(--border); font-size: 12px;">
                <p>Generated by Vortex Scanner | Developed by Mehmet Tezcan (KTÜN)</p>
            </div>
        </div>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return filename