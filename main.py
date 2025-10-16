import os
from flask import Flask, jsonify, render_template_string
from google.cloud import compute_v1

app = Flask(__name__)

# ---------- Simple HTML UI ----------
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>GCP Security Audit Report</title>
<style>
body { font-family: Arial, sans-serif; background: #f4f4f9; padding: 20px; }
h1 { color: #2b5cd6; }
table { border-collapse: collapse; width: 100%; background: white; }
th, td { padding: 10px; border-bottom: 1px solid #ddd; text-align: left; }
th { background: #2b5cd6; color: white; }
</style>
</head>
<body>
<h1>🔒 GCP Security Audit Report</h1>
<p><b>Project:</b> {{ project }}</p>
<p><b>Findings:</b></p>
<table>
<tr><th>Resource</th><th>Finding</th></tr>
{% for f in findings %}
<tr><td>{{ f['resource'] }}</td><td>{{ f['finding'] }}</td></tr>
{% endfor %}
</table>
</body>
</html>
"""

# ---------- Security Scan Logic ----------
def scan_resources(project_id):
    findings = []
    try:
        compute_client = compute_v1.InstancesClient()
        zones = ["us-central1-a", "us-central1-b", "us-central1-c", "us-central1-f"]
        for zone in zones:
            try:
                request = compute_v1.ListInstancesRequest(project=project_id, zone=zone)
                for instance in compute_client.list(request=request):
                    if instance.network_interfaces:
                        for iface in instance.network_interfaces:
                            if iface.access_configs:
                                findings.append({
                                    "resource": instance.name,
                                    "finding": f"VM '{instance.name}' in {zone} has a public IP"
                                })
            except Exception as inner_e:
                continue
    except Exception as e:
        findings.append({"resource": "Compute Engine", "finding": f"Error during scan: {e}"})

    if not findings:
        findings.append({"resource": "All", "finding": "✅ No public IPs found"})

    return findings

# ---------- Routes ----------
@app.route('/')
def home():
    project_id = os.environ.get("GCP_PROJECT", "unknown")
    findings = scan_resources(project_id)
    return render_template_string(TEMPLATE, project=project_id, findings=findings)

@app.route('/run')
def run_scan():
    """Endpoint for Cloud Scheduler"""
    project_id = os.environ.get("GCP_PROJECT", "unknown")
    findings = scan_resources(project_id)
    return jsonify(findings)

def main(request):
    """Cloud Function entrypoint"""
    return home()
