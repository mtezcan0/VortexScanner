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
                --warning: #d29922; --border: #30363d;
            }}
            body {{ font-family: 'Inter', -apple-system, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 40px; }}
            .header {{ border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
            .stats-container {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }}
            .stat-card {{ background: var(--card); padding: 25px; border-radius: 12px; border: 1px solid var(--border); text-align: center; }}
            .stat-val {{ display: block; font-size: 36px; font-weight: 800; color: var(--accent); }}
            .stat-label {{ color: #8b949e; text-transform: uppercase; font-size: 11px; margin-top: 8px; font-weight: 600; }}
            table {{ width: 100%; border-collapse: separate; border-spacing: 0; background: var(--card); border-radius: 12px; border: 1px solid var(--border); overflow: hidden; }}
            th {{ background: #21262d; padding: 18px; text-align: left; color: #8b949e; font-size: 12px; text-transform: uppercase; }}
            td {{ padding: 18px; border-top: 1px solid var(--border); font-size: 14px; vertical-align: top; }}
            .status-badge {{ padding: 6px 12px; border-radius: 20px; font-size: 11px; font-weight: bold; border: 1px solid transparent; }}
            .status-200 {{ background: rgba(35, 134, 54, 0.1); color: #3fb950; border-color: rgba(63, 185, 80, 0.3); }}
            .status-error {{ background: rgba(248, 81, 73, 0.1); color: var(--danger); border-color: rgba(248, 81, 73, 0.3); }}
            .vuln-alert {{ background: rgba(248, 81, 73, 0.1); padding: 15px; border-radius: 8px; border-left: 4px solid var(--danger); margin-top: 15px; }}
            .vuln-tag {{ color: var(--danger); font-family: monospace; font-size: 13px; display: block; margin-top: 5px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div><h1>VORTEX SCANNER</h1><p style="color: #8b949e;">Target: <strong>{target}</strong></p></div>
            <div style="text-align: right; color: #8b949e;">{timestamp}<br>Advanced Recon 2026</div>
        </div>
        <div class="stats-container">
            <div class="stat-card"><span class="stat-val">{total_scanned}</span><span class="stat-label">Discovery</span></div>
            <div class="stat-card"><span class="stat-val">{active_sites}</span><span class="stat-label">Live</span></div>
            <div class="stat-card"><span class="stat-val">{total_forms}</span><span class="stat-label">Forms</span></div>
            <div class="stat-card"><span class="stat-val" style="color:var(--danger)">{total_vulns}</span><span class="stat-label">Vulns</span></div>
        </div>
        <table>
            <thead><tr><th>Target Endpoint</th><th>Network Info</th><th>Connectivity</th><th>Security Findings</th></tr></thead>
            <tbody>
    """

    for sub, data in results_dict.items():
        findings = data.get('findings', {})
        vulns = findings.get('vulnerabilities', [])
        status = data.get('status')
        status_cls = "status-200" if status == 200 else "status-error"
        status_text = "LIVE" if status == 200 else str(status)
        
        html_content += f"""
            <tr>
                <td style="color: var(--accent); font-weight: bold;">{sub}</td>
                <td style="color: #8b949e; font-family: monospace;">{data.get('ip', 'N/A')}</td>
                <td><span class="status-badge {status_cls}">{status_text}</span></td>
                <td>
        """

        if findings.get('forms_found', 0) > 0:
            html_content += f'<div style="margin-bottom: 5px;">{findings["forms_found"]} web form(s) discovered.</div>'
        
        if vulns:
            html_content += f'<div class="vuln-alert"><strong>CRITICAL VULNERABILITIES:</strong>'
            for v in vulns:
                type_v = html.escape(str(v.get('type') or 'Unknown'))
                payload_v = html.escape(str(v.get('payload') or 'N/A'))
                param_v = html.escape(str(v.get('parameter') or 'Multiple'))
                html_content += f'<span class="vuln-tag">[!] {type_v} on "{param_v}" with {payload_v}</span>'
            html_content += '</div>'
        elif status == 200 and findings.get('forms_found', 0) == 0:
            html_content += '<span style="color: #484f58;">No active entry points found.</span>'

        html_content += "</td></tr>"

    html_content += """
            </tbody>
        </table>
        <div style="text-align: center; margin-top: 40px; color: #484f58; font-size: 12px;">
            Developed by Mehmet Tezcan (KTÜN) | Vortex Cyber Scanner 2026
        </div>
    </body>
    </html>
    """
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    return filename