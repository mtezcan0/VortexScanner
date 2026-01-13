import os
import datetime
import html

def generate_full_report(target, results_dict):
   
    if not results_dict:
        return None

    if not os.path.exists("reports"):
        os.makedirs("reports")

    total_scanned = len(results_dict)
    active_sites = sum(1 for data in results_dict.values() if data.get('status') == 200)
    forms_found = sum(len(data.get('forms', [])) for data in results_dict.values())
    total_vulns = sum(len(data.get('vulnerabilities', [])) for data in results_dict.values())
    
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
            :root {{ --bg: #0d1117; --card: #161b22; --text: #c9d1d9; --accent: #58a6ff; --success: #238636; --danger: #da3633; --warning: #d29922; }}
            body {{ font-family: 'Segoe UI', sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 40px; }}
            .header {{ border-bottom: 1px solid #30363d; padding-bottom: 20px; margin-bottom: 30px; }}
            h1 {{ color: var(--accent); margin: 0; font-size: 28px; }}
            .stats-container {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
            .stat-card {{ background: var(--card); padding: 20px; border-radius: 10px; border: 1px solid #30363d; text-align: center; }}
            .stat-val {{ display: block; font-size: 32px; font-weight: bold; color: var(--accent); }}
            .stat-label {{ color: #8b949e; text-transform: uppercase; font-size: 12px; margin-top: 5px; }}
            .val-danger {{ color: var(--danger) !important; }}
            table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 10px; overflow: hidden; }}
            th {{ background: #21262d; padding: 15px; text-align: left; color: #8b949e; font-size: 13px; }}
            td {{ padding: 15px; border-top: 1px solid #30363d; font-size: 14px; vertical-align: top; }}
            .status-badge {{ padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }}
            .status-200 {{ background: rgba(35, 134, 54, 0.2); color: #3fb950; }}
            .status-error {{ background: rgba(218, 54, 51, 0.2); color: #f85149; }}
            .forms-container {{ background: #0d1117; padding: 10px; border-radius: 6px; border-left: 3px solid var(--warning); margin-top: 10px; }}
            .vuln-container {{ background: rgba(218, 54, 51, 0.1); padding: 10px; border-radius: 6px; border-left: 3px solid var(--danger); margin-top: 10px; }}
            .vuln-list {{ margin: 5px 0 0 15px; padding: 0; color: #f85149; list-style-type: none; font-family: monospace; font-size: 12px; }}
            .input-tag {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 11px; margin-right: 5px; color: #8b949e; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>VORTEX SCANNER - SECURITY RECON REPORT</h1>
            <p style="color: #8b949e;">Target: <strong>{target}</strong> | Generated: {timestamp}</p>
        </div>

        <div class="stats-container">
            <div class="stat-card"><span class="stat-val">{total_scanned}</span><span class="stat-label">Subdomains</span></div>
            <div class="stat-card"><span class="stat-val">{active_sites}</span><span class="stat-label">Active Services</span></div>
            <div class="stat-card"><span class="stat-val">{forms_found}</span><span class="stat-label">Forms Detected</span></div>
            <div class="stat-card"><span class="stat-val val-danger">{total_vulns}</span><span class="stat-label">Critical Vulns</span></div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>SUBDOMAIN</th>
                    <th>IP ADDRESS</th>
                    <th>STATUS</th>
                    <th>ATTACK SURFACE & VULNERABILITIES</th>
                </tr>
            </thead>
            <tbody>
    """

    for sub, data in results_dict.items():
        status_cls = "status-200" if data.get('status') == 200 else "status-error"
        status_text = "LIVE" if data.get('status') == 200 else str(data.get('status'))
        
        html_content += f"""
            <tr>
                <td style="font-weight: bold; color: #58a6ff;">{sub}</td>
                <td style="font-family: monospace;">{data.get('ip', 'N/A')}</td>
                <td><span class="status-badge {status_cls}">{status_text}</span></td>
                <td>
        """

        if 'forms' in data and data['forms']:
            for i, form in enumerate(data['forms'], 1):
                safe_action = html.escape(form['action'])
                html_content += f"""
                <div class="forms-container">
                    <strong>Form {i}:</strong> {form['method'].upper()} &rarr; {safe_action}<br>
                    <div style="margin-top: 8px;">
                """
                for inp in form['inputs']:
                    safe_name = html.escape(inp.get('name', 'unnamed'))
                    html_content += f'<span class="input-tag">{safe_name} ({inp.get("type", "text")})</span>'
                html_content += "</div></div>"
        
        if 'vulnerabilities' in data and data['vulnerabilities']:
            html_content += f"""
            <div class="vuln-container">
                <b style="color: var(--danger);">Critical Vulnerabilities Found:</b>
                <ul class="vuln-list">
            """
            for v in data['vulnerabilities']:
                safe_vuln = html.escape(v)
                html_content += f"<li>[!] {safe_vuln}</li>"
            html_content += "</ul></div>"

        if not data.get('forms') and not data.get('vulnerabilities'):
            html_content += '<span style="color: #484f58;">No security findings.</span>'

        html_content += "</td></tr>"

    html_content += """
            </tbody>
        </table>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return filename