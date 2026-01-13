import os
import datetime
import html

def generate_reports(target, results_dict):
    if not results_dict:
        return None

    if not os.path.exists("reports"):
        os.makedirs("reports")

    total_scanned = len(results_dict)
    active_sites = sum(1 for data in results_dict.values() if data.get('status') == 200)
    
    total_forms = 0
    total_vulns = 0
    for data in results_dict.values():
        findings = data.get('findings', {})
        total_forms += findings.get('forms_found', 0)
        total_vulns += len(findings.get('vulnerabilities', []))
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"reports/{target}_vortex_report_{file_ts}.html"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Vortex Security Report - {target}</title>
        <style>
            :root {{ 
                --bg: #0d1117; --card: #161b22; --text: #c9d1d9; 
                --accent: #58a6ff; --success: #238636; --danger: #f85149; 
                --warning: #d29922; --border: #30363d; --header-bg: #161b22;
            }}
            body {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 40px; line-height: 1.5; }}
            .header {{ border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
            .header-info h1 {{ color: var(--accent); margin: 0; font-size: 32px; letter-spacing: -1px; }}
            .stats-container {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }}
            .stat-card {{ background: var(--card); padding: 25px; border-radius: 12px; border: 1px solid var(--border); text-align: center; transition: transform 0.2s; }}
            .stat-card:hover {{ transform: translateY(-5px); border-color: var(--accent); }}
            .stat-val {{ display: block; font-size: 36px; font-weight: 800; color: var(--accent); }}
            .stat-label {{ color: #8b949e; text-transform: uppercase; font-size: 11px; font-weight: 600; margin-top: 8px; letter-spacing: 1px; }}
            .val-danger {{ color: var(--danger) !important; }}
            table {{ width: 100%; border-collapse: separate; border-spacing: 0; background: var(--card); border-radius: 12px; border: 1px solid var(--border); overflow: hidden; }}
            th {{ background: #21262d; padding: 18px; text-align: left; color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
            td {{ padding: 18px; border-top: 1px solid var(--border); font-size: 14px; vertical-align: top; }}
            .status-badge {{ padding: 6px 12px; border-radius: 20px; font-size: 11px; font-weight: bold; border: 1px solid transparent; }}
            .status-200 {{ background: rgba(35, 134, 54, 0.1); color: #3fb950; border-color: rgba(63, 185, 80, 0.3); }}
            .status-error {{ background: rgba(248, 81, 73, 0.1); color: var(--danger); border-color: rgba(248, 81, 73, 0.3); }}
            .surface-item {{ background: #0d1117; padding: 15px; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 10px; }}
            .vuln-alert {{ background: rgba(248, 81, 73, 0.1); padding: 15px; border-radius: 8px; border-left: 4px solid var(--danger); margin-top: 15px; }}
            .vuln-tag {{ color: var(--danger); font-family: 'Fira Code', monospace; font-size: 13px; display: block; margin-top: 5px; }}
            .input-tag {{ background: #21262d; padding: 3px 8px; border-radius: 6px; font-size: 11px; margin-right: 6px; color: #8b949e; border: 1px solid var(--border); }}
            .method-badge {{ font-weight: bold; color: var(--warning); margin-right: 10px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="header-info">
                <h1>VORTEX SCANNER</h1>
                <p style="color: #8b949e; margin: 5px 0 0 0;">Target Analytics for <strong>{target}</strong></p>
            </div>
            <div style="text-align: right; color: #8b949e; font-size: 13px;">
                Generated: {timestamp}<br>
                <span style="color: var(--accent);">Advanced Recon Edition 2026</span>
            </div>
        </div>

        <div class="stats-container">
            <div class="stat-card"><span class="stat-val">{total_scanned}</span><span class="stat-label">Discovery Count</span></div>
            <div class="stat-card"><span class="stat-val">{active_sites}</span><span class="stat-label">Active Endpoints</span></div>
            <div class="stat-card"><span class="stat-val">{total_forms}</span><span class="stat-label">Entry Points</span></div>
            <div class="stat-card"><span class="stat-val val-danger">{total_vulns}</span><span class="stat-label">Exploitable Vulns</span></div>
        </div>

        <table>
            <thead>
                <tr>
                    <th style="width: 25%;">Target Endpoint</th>
                    <th style="width: 15%;">Network Info</th>
                    <th style="width: 10%;">Connectivity</th>
                    <th style="width: 50%;">Analysis & Security Findings</th>
                </tr>
            </thead>
            <tbody>
    """

    for sub, data in results_dict.items():
        status = data.get('status')
        status_cls = "status-200" if status == 200 else "status-error"
        status_text = "LIVE" if status == 200 else str(status)
        findings = data.get('findings', {})
        vulns = findings.get('vulnerabilities', [])
        
        html_content += f"""
            <tr>
                <td style="font-weight: bold; color: var(--accent);">{sub}</td>
                <td style="font-family: 'Fira Code', monospace; font-size: 12px; color: #8b949e;">{data.get('ip', 'N/A')}</td>
                <td><span class="status-badge {status_cls}">{status_text}</span></td>
                <td>
        """

        if findings.get('forms_found', 0) > 0:
            html_content += f'<div class="surface-item"><strong>Entry Points:</strong> {findings["forms_found"]} Web Form(s) Detected</div>'
        
        if vulns:
            html_content += f'<div class="vuln-alert"><strong>CRITICAL SECURITY BREACH:</strong>'
            for v in vulns:
                type_v = html.escape(v.get('type', 'Unknown'))
                payload_v = html.escape(v.get('payload', 'N/A'))
                param_v = html.escape(v.get('parameter', 'Multiple'))
                html_content += f'<span class="vuln-tag">[!] {type_v} detected via "{param_v}" using payload: {payload_v}</span>'
            html_content += '</div>'

        if not vulns and findings.get('forms_found', 0) == 0:
            html_content += '<span style="color: #484f58; font-style: italic;">No active attack surface found on this endpoint.</span>'

        html_content += "</td></tr>"

    html_content += """
            </tbody>
        </table>
        <div style="text-align: center; margin-top: 40px; color: #484f58; font-size: 12px;">
            &copy; 2026 Vortex Cyber Scanner. Developed by Mehmet Tezcan (KTÜN). Internal Audit Use Only.
        </div>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return filename